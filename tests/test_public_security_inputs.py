"""NEW pure public input contracts: only owned inert data, never the actual project inventory."""
from __future__ import annotations

import copy
import hashlib
import io
import json
from pathlib import Path
import tempfile
import tarfile
import unittest
import zipfile
from datetime import datetime, timedelta, timezone

from getzilla import security_artifacts as artifacts, security_licenses as licenses
from getzilla import security_tools
from getzilla import security_inventory
from getzilla import security_cli
from getzilla import security_license_acquisition as acquisition
from getzilla.security_data import SecurityDataError
from unittest.mock import patch
from types import SimpleNamespace

NOW = datetime(2026, 11, 9, 12, tzinfo=timezone.utc)
ROOT = Path(__file__).resolve().parents[1]
MIT = json.loads((ROOT / 'tests/fixtures/security-license-texts.json').read_text())['MIT']['text'].encode()
POLICY = {'schema_version': 1, 'project_repository': 'github.com/owned/project',
          'auto_allow': ['MIT', 'Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', 'ISC', '0BSD'],
          'usage_distribution': {'build-ci': 'internal'}}


def sha(body):
    return hashlib.sha256(body).hexdigest()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def git_blob(body):
    return hashlib.sha1(b'blob ' + str(len(body)).encode() + b'\0' + body).hexdigest()


def action_fixture(directory):
    files = {'LICENSE': MIT, 'action.yml': b'name: owned\nruns:\n  using: composite\n  steps:\n    - run: printf public\n      shell: bash\n'}
    tree_body = b''.join(b'100644 ' + name.encode() + b'\0' + bytes.fromhex(git_blob(body)) for name, body in sorted(files.items()))
    tree_id = hashlib.sha1(b'tree ' + str(len(tree_body)).encode() + b'\0' + tree_body).hexdigest()
    revision = 'b' * 40
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w') as archive:
        for name, body in files.items():
            info = zipfile.ZipInfo('src/' + name)
            info.external_attr = 0o100644 << 16
            archive.writestr(info, body)
    payload = output.getvalue()
    subject = {'kind': 'github-action', 'reference': 'owned/action@' + revision,
               'manifest': '.github/workflows/verify.yml', 'line': 4, 'usage': 'build-ci', 'source_sha256': 'a' * 64}
    commit = encoded({'sha': revision, 'tree': {'sha': tree_id}})
    tree = encoded({'sha': tree_id, 'truncated': False, 'tree': [
        {'path': name, 'mode': '100644', 'type': 'blob', 'sha': git_blob(body), 'size': len(body)} for name, body in sorted(files.items())]})
    proof = encoded({'schema_version': 1, 'kind': 'artifact-component-inventory', 'artifact_sha256': sha(payload),
        'complete': True, 'unresolved': [], 'components': [{'id': 'owned', 'expression': 'MIT', 'requires': [],
            'license_paths': ['src/LICENSE'], 'notice_paths': [],
            'files': [{'path': 'src/' + name, 'sha256': sha(body), 'bytes': len(body)} for name, body in sorted(files.items())]}]})
    record = {'kind': 'action', 'schema_version': 1, 'subject': subject, 'filename': 'source.zip',
              'path': 'objects/' + sha(payload), 'sha256': sha(payload), 'bytes': len(payload),
              'context': {'manifest': subject['manifest'], 'usage': 'build-ci'}, 'acquired_at': NOW.isoformat(),
              'origin': {'kind': 'github-source', 'index_url': 'https://api.github.com/repos/owned/action/git/commits/' + revision,
                         'index_path': 'indexes/' + sha(commit) + '.json', 'index_sha256': sha(commit),
                         'artifact_url': 'https://api.github.com/repos/owned/action/zipball/' + revision,
                         'tree_path': 'indexes/' + sha(tree) + '.json', 'tree_sha256': sha(tree), 'archive_root': 'src'},
              'components': {'path': 'proofs/' + sha(proof) + '.json', 'sha256': sha(proof)}}
    for name, body in ((record['path'], payload), (record['origin']['index_path'], commit),
                       (record['origin']['tree_path'], tree), (record['components']['path'], proof)):
        path = directory / name
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_bytes(body)
    inventory = {'schema_version': 1, 'complete': True, 'gaps': [], 'dependencies': [], 'tools': [subject], 'images': []}
    inventory['digest'] = sha(encoded(inventory))
    bundle = {'schema_version': 1, 'inventory_digest': inventory['digest'],
              'last_verified_sync_utc': NOW.isoformat(), 'records': [record], 'gaps': []}
    (directory / 'manifest.json').write_bytes(encoded(bundle))
    return inventory, record, bundle


def release_fixture(directory):
    inventory, record, bundle = action_fixture(directory)
    reference = 'https://github.com/owned/tool/releases/download/v1/source.zip'
    record['kind'] = 'tool'
    record['subject'].update(kind='release-tool', reference=reference, artifact_sha256=record['sha256'], platform='linux/amd64')
    release = encoded({'tag_name': 'v1', 'target_commitish': 'b' * 40, 'assets': [
        {'name': 'source.zip', 'browser_download_url': reference, 'size': record['bytes'], 'digest': 'sha256:' + record['sha256']}]})
    record['origin'] = {'kind': 'github-release', 'index_url': 'https://api.github.com/repos/owned/tool/releases/tags/v1',
        'index_path': 'indexes/' + sha(release) + '.json', 'index_sha256': sha(release),
        'artifact_url': reference, 'source_commit': 'b' * 40}
    (directory / record['origin']['index_path']).write_bytes(release)
    inventory['digest'] = sha(encoded({key: value for key, value in inventory.items() if key != 'digest'}))
    bundle['inventory_digest'] = inventory['digest']
    (directory / 'manifest.json').write_bytes(encoded(bundle))
    return inventory, record, bundle


class PublicReleaseLicenseTests(unittest.TestCase):
    def test_exact_source_pinned_release_archive_retains_component_licenses(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            inventory, record, _ = release_fixture(directory)
            report = licenses.evaluate_artifacts(inventory, directory, POLICY, now=NOW)
            self.assertEqual(report['status'], 'pass', report)
            self.assertEqual(report['details'][0]['artifact_sha256'], record['sha256'])
            self.assertTrue(licenses.artifact_catalog_source(inventory, directory, POLICY, now=NOW)['coverage']['complete'])

    def test_changed_binary_origin_platform_or_unretained_dependency_refuses(self):
        for variant in ('digest', 'platform', 'origin', 'dependency'):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                inventory, record, bundle = release_fixture(directory)
                if variant == 'digest':
                    record['subject']['artifact_sha256'] = 'c' * 64
                elif variant == 'platform':
                    record['subject']['platform'] = 'unknown'
                elif variant == 'origin':
                    record['origin']['artifact_url'] = 'https://unowned.invalid/source.zip'
                else:
                    path = directory / record['components']['path']
                    proof = json.loads(path.read_bytes())
                    proof['components'][0]['requires'] = ['unretained']
                    raw = encoded(proof)
                    path.write_bytes(raw)
                    record['components']['sha256'] = sha(raw)
                (directory / 'manifest.json').write_bytes(encoded(bundle))
                self.assertEqual(licenses.evaluate_artifacts(inventory, directory, POLICY, now=NOW)['status'], 'fail')


def image_fixture(directory):
    inventory, record, bundle = action_fixture(directory)
    layer_output = io.BytesIO()
    inner = {'LICENSE': MIT, 'bin/public': b'public owned inert bytes'}
    with tarfile.open(fileobj=layer_output, mode='w') as layer:
        for name, body in inner.items():
            member = tarfile.TarInfo(name)
            member.size = len(body)
            member.mode = 0o644
            layer.addfile(member, io.BytesIO(body))
    layer = layer_output.getvalue()
    config = encoded({'architecture': 'amd64', 'os': 'linux', 'rootfs': {'type': 'layers', 'diff_ids': ['sha256:' + sha(layer)]}})
    def descriptor(body, media):
        return {'mediaType': media, 'digest': 'sha256:' + sha(body), 'size': len(body)}
    manifest = encoded({'schemaVersion': 2, 'mediaType': 'application/vnd.oci.image.manifest.v1+json',
        'config': descriptor(config, 'application/vnd.oci.image.config.v1+json'),
        'layers': [descriptor(layer, 'application/vnd.oci.image.layer.v1.tar')]})
    selected = descriptor(manifest, 'application/vnd.oci.image.manifest.v1+json')
    selected['platform'] = {'os': 'linux', 'architecture': 'amd64'}
    outer = {'oci-layout': encoded({'imageLayoutVersion': '1.0.0'}),
        'index.json': encoded({'schemaVersion': 2, 'manifests': [selected]}),
        'blobs/sha256/' + sha(manifest): manifest, 'blobs/sha256/' + sha(config): config,
        'blobs/sha256/' + sha(layer): layer}
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w') as archive:
        for name, body in outer.items():
            member = zipfile.ZipInfo(name)
            member.external_attr = 0o100644 << 16
            archive.writestr(member, body)
    payload = output.getvalue()
    all_files = {'oci/' + name: body for name, body in outer.items()}
    all_files.update({'layers/' + sha(layer) + '/' + name: body for name, body in inner.items()})
    subject = {'kind': 'oci-image', 'reference': 'registry.example/owned/public@sha256:' + sha(manifest),
        'platform': 'linux/amd64', 'manifest': 'compose.yml', 'line': 3, 'source_sha256': 'a' * 64, 'usage': 'build-ci'}
    proof = encoded({'schema_version': 1, 'kind': 'artifact-component-inventory', 'artifact_sha256': sha(payload),
        'complete': True, 'unresolved': [], 'components': [{'id': 'owned', 'expression': 'MIT', 'requires': [],
            'license_paths': ['layers/' + sha(layer) + '/LICENSE'], 'notice_paths': [],
            'files': [{'path': path, 'sha256': sha(body), 'bytes': len(body)} for path, body in sorted(all_files.items())]}]})
    record.update(kind='image', subject=subject, filename='image.zip', path='objects/' + sha(payload),
        sha256=sha(payload), bytes=len(payload), context={'manifest': 'compose.yml', 'usage': 'build-ci'},
        origin={'kind': 'oci-layout', 'manifest_digest': 'sha256:' + sha(manifest)},
        components={'path': 'proofs/' + sha(proof) + '.json', 'sha256': sha(proof)})
    for path, body in ((record['path'], payload), (record['components']['path'], proof)):
        (directory / path).write_bytes(body)
    inventory['tools'] = []
    inventory['images'] = [subject]
    inventory['digest'] = sha(encoded({key: value for key, value in inventory.items() if key != 'digest'}))
    bundle['inventory_digest'] = inventory['digest']
    (directory / 'manifest.json').write_bytes(encoded(bundle))
    return inventory, record, bundle


class PublicImageContractTests(unittest.TestCase):
    def test_exact_platform_layers_and_complete_license_graph_can_qualify(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            inventory, record, _ = image_fixture(directory)
            report = licenses.evaluate_artifacts(inventory, directory, POLICY, now=NOW)
            self.assertEqual(report['status'], 'pass', report)
            self.assertEqual(report['details'][0]['artifact_sha256'], record['sha256'])
            self.assertTrue(licenses.artifact_catalog_source(inventory, directory, POLICY, now=NOW)['coverage']['complete'])

    def test_wrong_platform_or_vulnerability_only_proof_never_clears_image_license(self):
        for variant in ('platform', 'partial', 'identity'):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                inventory, record, bundle = image_fixture(directory)
                if variant == 'platform':
                    record['subject']['platform'] = 'linux/arm64'
                elif variant == 'identity':
                    record['origin']['manifest_digest'] = 'sha256:' + 'c' * 64
                else:
                    body = encoded({'Results': [], 'SchemaVersion': 2})
                    (directory / record['components']['path']).write_bytes(body)
                    record['components']['sha256'] = sha(body)
                (directory / 'manifest.json').write_bytes(encoded(bundle))
                self.assertEqual(licenses.evaluate_artifacts(inventory, directory, POLICY, now=NOW)['status'], 'fail')

    def test_unbounded_image_transport_refuses_before_any_tool_or_process(self):
        inventory = {'images': [{'reference': 'registry.example/public@sha256:' + 'a' * 64}]}
        with (patch.object(security_tools, 'pinned_tool', side_effect=AssertionError('must not select tool')),
              patch.object(security_tools, '_process', side_effect=AssertionError('must not start transport'))):
            with self.assertRaises(SecurityDataError):
                security_tools.refresh_images(inventory, Path('not-used'))


class SourceWorkflowDeclarationTests(unittest.TestCase):
    command = '''set -euo pipefail
version=$(sed -n 's/^ARG TOOL_VERSION=//p' pins.Dockerfile)
digest=$(sed -n 's/^ARG TOOL_SHA256=//p' pins.Dockerfile)
mkdir -p "$RUNNER_TEMP/tool"
curl -fsSL -o "$RUNNER_TEMP/tool/public" "https://github.com/owned/tool/releases/download/v${version}/public"
echo "${digest}  $RUNNER_TEMP/tool/public" | sha256sum -c -
chmod 0755 "$RUNNER_TEMP/tool/public"
'''

    def test_bound_arg_download_is_declaration_only_with_exact_source_inputs(self):
        pins = b'ARG TOOL_VERSION=1.2.3\nARG TOOL_SHA256=' + b'a' * 64 + b'\n'
        reads = []
        def read(path):
            reads.append(path)
            self.assertEqual(path, 'pins.Dockerfile')
            return pins
        tools, gaps = security_inventory.workflow_downloads(self.command, '.github/workflows/public.yml', 4, b'workflow', read)
        self.assertEqual(gaps, [])
        self.assertEqual(tools[0]['kind'], 'release-tool')
        self.assertEqual(tools[0]['artifact_sha256'], 'a' * 64)
        self.assertEqual(tools[0]['reference'], 'https://github.com/owned/tool/releases/download/v1.2.3/public')
        self.assertEqual(tools[0]['source_sha256'], sha(b'workflow'))
        self.assertEqual(tools[0]['pin_sources'][0]['sha256'], sha(pins))
        self.assertTrue(reads)
        self.assertNotIn('status', tools[0])

    def test_opaque_flow_early_use_mismatched_target_or_missing_hash_stays_unresolved(self):
        variants = [self.command.replace('set -euo pipefail', 'if true; then'),
                    self.command.replace('echo "${digest}', 'chmod 0755 "$RUNNER_TEMP/tool/public"\necho "${digest}'),
                    self.command.replace('${digest}  $RUNNER_TEMP/tool/public', '${digest}  $RUNNER_TEMP/other'),
                    self.command.replace('sha256sum -c -', 'printf ignored')]
        for command in variants:
            with self.subTest(command=command):
                tools, gaps = security_inventory.workflow_downloads(command, '.github/workflows/public.yml', 4,
                    b'workflow', lambda path: b'ARG TOOL_VERSION=1.2.3\nARG TOOL_SHA256=' + b'a' * 64 + b'\n')
                self.assertTrue(gaps)
                self.assertEqual(tools[0]['kind'], 'script-download')


class SharedCatalogPublicationTests(unittest.TestCase):
    def test_package_refresh_does_not_overwrite_existing_family_or_renew_its_time(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            inventory, record, _ = action_fixture(directory)
            before = copy.deepcopy(record)
            observed = acquisition.acquire_pypi([], directory, inventory_digest=inventory['digest'],
                fetch=lambda *args, **kwargs: self.fail('no fetch required'), now=NOW + timedelta(seconds=10))
            self.assertEqual(observed['records'], [before])
            self.assertEqual(observed['last_verified_sync_utc'], NOW.isoformat())
            self.assertEqual(observed['records'][0]['acquired_at'], before['acquired_at'])

    def test_failed_saved_proof_refresh_preserves_previous_manifest(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            inventory, record, _ = action_fixture(directory)
            before = (directory / 'manifest.json').read_bytes()
            (directory / record['components']['path']).write_bytes(b'changed')
            with self.assertRaises(artifacts.ArtifactError):
                acquisition.acquire_pypi([], directory, inventory_digest=inventory['digest'],
                    fetch=lambda *args, **kwargs: self.fail('no fetch required'), now=NOW)
            self.assertEqual((directory / 'manifest.json').read_bytes(), before)

    def test_postreplacement_durability_failure_is_uncertain_without_false_rollback(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            inventory, _record, _bundle = action_fixture(directory)
            before = (directory / 'manifest.json').read_bytes()
            calls = []
            def fail_after_replacement(descriptor):
                calls.append(descriptor)
                if len(calls) == 2:
                    raise OSError('owned synthetic durability refusal')
            with patch.object(acquisition.os, 'fsync', side_effect=fail_after_replacement):
                with self.assertRaises(artifacts.ArtifactError) as caught:
                    acquisition.acquire_pypi([], directory, inventory_digest=inventory['digest'], now=NOW)
            self.assertEqual(caught.exception.code, 'artifact-publication-uncertain')
            self.assertNotEqual((directory / 'manifest.json').read_bytes(), before)


class PublicInputProfileTests(unittest.TestCase):
    def values(self):
        source = {'head_sha': 'a' * 40, 'tree_sha': 'b' * 40, 'checker_sha': 'c' * 40,
                  'checker_tree_sha': 'd' * 40, 'candidate_clean': True, 'checker_clean': True, 'same_project': False}
        inventory = {'complete': True, 'gaps': [], 'digest': 'a' * 64, 'dependencies': [], 'tools': [], 'images': []}
        roots = {'database': '/owned/db', 'artifacts': '/owned/artifacts', 'tools': '/owned/tools'}
        run = {'provider': 'github-actions', 'repository': 'owned/project', 'run_id': '42', 'run_attempt': '3', 'head_sha': 'a' * 40}
        return source, inventory, roots, run, 'b' * 64

    def test_current_run_profile_is_declaration_without_scan_or_attestation(self):
        values = self.values()
        profile = security_cli.input_profile(*values, now=NOW)
        self.assertEqual(profile['kind'], 'public-security-input-profile')
        self.assertEqual(profile['observed_counts'], {'dependencies': 0, 'tools': 0, 'images': 0})
        self.assertNotIn('status', profile)
        self.assertEqual(security_cli.validate_input_profile(profile, *values, now=NOW), profile)

    def test_substituted_attempt_source_roots_policy_limits_or_age_refuses(self):
        values = self.values()
        for variant in ('attempt', 'source', 'roots', 'policy', 'limits', 'extra', 'stale', 'future'):
            with self.subTest(variant=variant):
                profile = security_cli.input_profile(*values, now=NOW)
                if variant == 'attempt':
                    profile['run'] = {**profile['run'], 'run_attempt': '2'}
                elif variant == 'source':
                    profile['source'] = {**profile['source'], 'checker_sha': 'e' * 40}
                elif variant == 'roots':
                    profile['roots'] = {**profile['roots'], 'database': '/other/db'}
                elif variant == 'policy':
                    profile['policy_sha256'] = 'c' * 64
                elif variant == 'limits':
                    profile['limits']['catalog_bytes'] *= 2
                elif variant == 'extra':
                    profile['status'] = 'pass'
                elif variant == 'stale':
                    profile['created_at'] = (NOW - timedelta(seconds=259201)).isoformat()
                else:
                    profile['created_at'] = (NOW + timedelta(seconds=1)).isoformat()
                # Rehashing a claim cannot turn it into the current producer/run.
                profile.pop('profile_sha256')
                profile['profile_sha256'] = sha(encoded(profile))
                with self.assertRaises(SecurityDataError):
                    security_cli.validate_input_profile(profile, *values, now=NOW)

    def test_refresh_without_explicit_profile_never_reaches_inventory_or_provisioner(self):
        with (patch.object(security_cli, 'collect_inventory', side_effect=AssertionError('not admitted')),
              patch.object(security_cli, 'provision_tools', side_effect=AssertionError('not admitted'))):
            with self.assertRaises(SecurityDataError):
                security_cli.evaluate(Path('/not-used'), Path('/not-used-db'), Path('/not-used-artifacts'),
                                      Path('/not-used-tools'), refresh=True, provision=True, now=NOW)

    def test_preparation_has_no_scan_credit_and_missing_required_source_never_passes(self):
        source, inventory, roots, run, policy = self.values()
        profile = security_cli.input_profile(source, inventory, roots, run, policy, now=NOW)
        names = ('security-inventory', 'known-vulnerabilities', 'security-kev', 'security-epss',
                 'security-malicious-packages', 'security-licenses', 'security-container-images')
        plan = [{'check_id': name, 'applicability': 'required' if name == 'security-inventory' else 'not_applicable',
                 'evidence': {'inventory_sha256': inventory['digest'], 'policy_sha256': policy, 'complete': True},
                 'data_sources': []} for name in names]
        result = security_cli.preparation_result(profile, source, source, plan, [], {'status': 'skip'}, now=NOW)
        self.assertEqual(result['status'], 'prepared')
        self.assertEqual(result['qualification'], 'UNVERIFIED')
        self.assertEqual(result['scan_outcomes'], [])
        inventory['dependencies'] = [{'ecosystem': 'PyPI'}]
        profile = security_cli.input_profile(source, inventory, roots, run, policy, now=NOW)
        result = security_cli.preparation_result(profile, source, source, plan, [], {'status': 'pass'}, now=NOW)
        self.assertEqual(result['status'], 'unavailable')
        self.assertIn('required-source-set-mismatch', result['gaps'])


class UnactivatedWorkflowBoundaryTests(unittest.TestCase):
    def test_earlier_capability_keeps_accepted_required_ci_unactivated(self):
        expected = {'.github/workflows/getzilla.yml': 'bd83ff0af1717c8ae03776c38eae3ed8fad3f52f24474562e7a6bbf15c218333', '.getzilla/templates/ci/github-actions-verify.yml': '4ef210a1d4e819d4a4d410e090b6fd96833f271c1b73ddfcd886124c459e8d37', 'tests/test_ci_gate.py': '83bcacb36968be3a242aca5bb54f0cbc4338ce0d708389f7001d2ad196dd2788'}
        for relative, digest in expected.items():
            with self.subTest(path=relative):
                self.assertEqual(sha((ROOT / relative).read_bytes()), digest)


class BoundedPreparationDispatchTests(unittest.TestCase):
    def observe(self, returncode):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile = {'schema_version': 1, 'profile_sha256': 'a' * 64}
            (root / 'profile.json').write_bytes(encoded(profile))
            report = {'kind': 'public-security-input-preparation', 'status': 'prepared',
                      'qualification': 'UNVERIFIED', 'profile': profile, 'profile_sha256': profile['profile_sha256']}
            calls = []
            def execute(command, cwd, environment, *, timeout):
                calls.append((command, timeout))
                (root / 'result.json').write_bytes(encoded(report))
                return SimpleNamespace(returncode=returncode, terminal_state='completed', cleanup_error=None)
            args = ['--root', str(root), '--database', str(root / 'db'), '--artifacts', str(root / 'artifacts'),
                    '--tools', str(root / 'tools'), '--input-profile', str(root / 'profile.json'),
                    '--prepare-inputs', '--json-out', str(root / 'result.json')]
            with (patch.object(security_cli, 'prepare_inputs', return_value=report),
                  patch.object(security_cli, 'execute', side_effect=execute)):
                status = security_cli.main(args)
            return status, calls, json.loads((root / 'result.json').read_bytes())

    def test_existing_runner_owns_the_whole_preparation_deadline(self):
        status, calls, report = self.observe(0)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][1], 600)
        self.assertIn('--prepare-inputs', calls[0][0])
        self.assertEqual(status, 0)
        self.assertEqual(report['qualification'], 'UNVERIFIED')

    def test_incomplete_worker_cannot_publish_prepared_credit(self):
        status, _calls, report = self.observe(124)
        self.assertNotEqual(status, 0)
        self.assertNotEqual(report['status'], 'prepared')


class PublicFamilyLicenseTests(unittest.TestCase):
    def test_record_age_is_inclusive_and_future_evidence_refuses(self):
        for seconds, expected in ((259200, 'pass'), (259201, 'fail'), (-1, 'fail')):
            with self.subTest(seconds=seconds), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                inventory, record, bundle = action_fixture(directory)
                record['acquired_at'] = (NOW - timedelta(seconds=seconds)).isoformat()
                bundle['last_verified_sync_utc'] = record['acquired_at']
                (directory / 'manifest.json').write_bytes(encoded(bundle))
                self.assertEqual(licenses.evaluate_artifacts(inventory, directory, POLICY, now=NOW)['status'], expected)

    def test_qualified_exact_action_can_satisfy_its_license_family(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            inventory, record, _bundle = action_fixture(directory)
            report = licenses.evaluate_artifacts(inventory, directory, POLICY, now=NOW)
            self.assertEqual(report['status'], 'pass', report)
            self.assertEqual(report['details'][0]['artifact_id'], artifacts.artifact_identity(record))
            self.assertEqual(report['details'][0]['selected_expression'], 'MIT')
            proof = licenses.artifact_catalog_source(inventory, directory, POLICY, now=NOW)
            self.assertTrue(proof['coverage']['complete'])
            self.assertEqual(proof['coverage']['record_count'], 1)

    def test_missing_changed_source_notice_or_partial_proof_cannot_clear_family(self):
        for variant in ('missing', 'hash', 'source', 'partial', 'notice', 'stale', 'usage'):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                inventory, record, bundle = action_fixture(directory)
                if variant == 'missing':
                    bundle['records'] = []
                elif variant == 'hash':
                    (directory / record['path']).write_bytes(b'changed')
                elif variant == 'source':
                    record['subject']['reference'] = 'owned/action@' + 'c' * 40
                elif variant in {'partial', 'notice'}:
                    path = directory / record['components']['path']
                    value = json.loads(path.read_bytes())
                    if variant == 'partial':
                        value['complete'] = False
                    else:
                        value['components'][0]['notice_paths'] = ['src/NOTICE']
                    raw = encoded(value)
                    path.write_bytes(raw)
                    record['components']['sha256'] = sha(raw)
                elif variant == 'stale':
                    record['acquired_at'] = (NOW - timedelta(seconds=259201)).isoformat()
                else:
                    record['context']['usage'] = 'runtime'
                (directory / 'manifest.json').write_bytes(encoded(bundle))
                report = licenses.evaluate_artifacts(inventory, directory, POLICY, now=NOW)
                self.assertEqual(report['status'], 'fail')


def collected_namespace_fixture(directory, variant):
    _inventory, record, _bundle = action_fixture(directory)
    committed = {'LICENSE': MIT, 'action.yml': b'name: owned\nruns:\n  using: composite\n  steps: []\n',
                 'entry': b'owned source A\n'}
    body = b''.join(b'100644 ' + name.encode() + b'\0' + bytes.fromhex(git_blob(raw))
                    for name, raw in sorted(committed.items()))
    tree_id = hashlib.sha1(b'tree ' + str(len(body)).encode() + b'\0' + body, usedforsecurity=False).hexdigest()
    rows = [{'path': name, 'mode': '100644', 'type': 'blob', 'sha': git_blob(raw), 'size': len(raw)}
            for name, raw in sorted(committed.items())]
    files = dict(committed)
    if variant == 'collision':
        files['entry/extra.txt'] = b'owned uncommitted descendant\n'
        rows.append({'path': 'entry/extra.txt', 'mode': '100644', 'type': 'blob',
                     'sha': git_blob(files['entry/extra.txt']), 'size': len(files['entry/extra.txt'])})
    elif variant == 'changed':
        files['entry'] = b'owned source B\n'
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w') as archive:
        for name, raw in sorted(files.items()):
            item = zipfile.ZipInfo('src/' + name)
            item.external_attr = 0o100644 << 16
            archive.writestr(item, raw)
    payload = output.getvalue()
    commit = encoded({'sha': 'b' * 40, 'tree': {'sha': tree_id}})
    tree = encoded({'sha': tree_id, 'truncated': False, 'tree': rows})
    proof = encoded({'schema_version': 1, 'kind': 'artifact-component-inventory', 'artifact_sha256': sha(payload),
        'complete': True, 'unresolved': [], 'components': [{'id': 'owned', 'expression': 'MIT', 'requires': [],
            'license_paths': ['src/LICENSE'], 'notice_paths': [],
            'files': [{'path': 'src/' + name, 'sha256': sha(raw), 'bytes': len(raw)} for name, raw in sorted(files.items())]}]})
    record.update(sha256=sha(payload), bytes=len(payload))
    record['origin'].update(index_sha256=sha(commit), tree_sha256=sha(tree))
    record['components']['sha256'] = sha(proof)
    for relative, raw in ((record['path'], payload), (record['origin']['index_path'], commit),
                          (record['origin']['tree_path'], tree), (record['components']['path'], proof)):
        (directory / relative).write_bytes(raw)
    return record, tree_id


class CollectedDeclarationAndNamespaceTests(unittest.TestCase):
    def test_opaque_postcheck_flow_retains_unresolved_declaration(self):
        pins = b'ARG TOOL_VERSION=1.2.3\nARG TOOL_SHA256=' + b'a' * 64 + b'\n'
        command = SourceWorkflowDeclarationTests.command
        def parse(text):
            return security_inventory.workflow_downloads(text, '.github/workflows/public.yml', 4,
                b'owned workflow', lambda name: pins, platform='linux/amd64')
        tools, gaps = parse(command)
        self.assertEqual(gaps, [])
        self.assertEqual(tools[0]['kind'], 'release-tool')
        opaque = command + 'printf replacement > "$RUNNER_TEMP/tool/public"\n"$RUNNER_TEMP/tool/public" --version\n'
        tools, gaps = parse(opaque)
        self.assertTrue(gaps)
        self.assertEqual(tools[0]['kind'], 'script-download')

    def test_file_descendant_cannot_borrow_an_unchanged_git_root(self):
        roots = []
        for variant in ('normal', 'changed', 'collision'):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                record, root_id = collected_namespace_fixture(directory, variant)
                roots.append(root_id)
                if variant == 'normal':
                    evidence = artifacts.family_evidence(directory, record)
                    self.assertEqual(len(evidence['members']), 3)
                else:
                    with self.assertRaises(artifacts.ArtifactError):
                        artifacts.family_evidence(directory, record)
        self.assertEqual(len(set(roots)), 1)


class ActionMetadataClosureTests(unittest.TestCase):
    def test_only_self_contained_composite_metadata_can_qualify(self):
        def evaluate(metadata, alternate=False):
            with tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                inventory, record, bundle = action_fixture(directory)
                files = {'LICENSE': MIT, 'action.yml': metadata.encode()}
                if alternate:
                    files['action.yaml'] = metadata.encode()
                tree_body = b''.join(b'100644 ' + name.encode() + b'\0' + bytes.fromhex(git_blob(body))
                                     for name, body in sorted(files.items()))
                tree_id = hashlib.sha1(b'tree ' + str(len(tree_body)).encode() + b'\0' + tree_body).hexdigest()
                output = io.BytesIO()
                with zipfile.ZipFile(output, 'w') as archive:
                    for name, body in files.items():
                        info = zipfile.ZipInfo('src/' + name)
                        info.external_attr = 0o100644 << 16
                        archive.writestr(info, body)
                payload = output.getvalue()
                commit = encoded({'sha': 'b' * 40, 'tree': {'sha': tree_id}})
                tree = encoded({'sha': tree_id, 'truncated': False, 'tree': [
                    {'path': name, 'mode': '100644', 'type': 'blob', 'sha': git_blob(body), 'size': len(body)}
                    for name, body in sorted(files.items())]})
                proof = encoded({'schema_version': 1, 'kind': 'artifact-component-inventory',
                    'artifact_sha256': sha(payload), 'complete': True, 'unresolved': [], 'components': [
                        {'id': 'owned', 'expression': 'MIT', 'requires': [], 'license_paths': ['src/LICENSE'],
                         'notice_paths': [], 'files': [{'path': 'src/' + name, 'sha256': sha(body), 'bytes': len(body)}
                                                      for name, body in sorted(files.items())]}]})
                record.update(sha256=sha(payload), bytes=len(payload))
                record['origin'].update(index_sha256=sha(commit), tree_sha256=sha(tree))
                record['components']['sha256'] = sha(proof)
                for relative, body in ((record['path'], payload), (record['origin']['index_path'], commit),
                                       (record['origin']['tree_path'], tree), (record['components']['path'], proof)):
                    (directory / relative).write_bytes(body)
                (directory / 'manifest.json').write_bytes(encoded(bundle))
                return licenses.evaluate_artifacts(inventory, directory, POLICY, now=NOW)['status']

        prefix = 'name: owned\nruns:\n  using: composite\n  steps: '
        for metadata in (prefix + '[]\n', prefix + '\n    - run: printf owned\n      shell: bash\n',
                         prefix + '[{run: "printf \'owned text\'", shell: sh}]\n'):
            with self.subTest(positive=metadata):
                self.assertEqual(evaluate(metadata), 'pass')
        unsupported = [
            prefix + '\n    - uses: missing/proof-action@' + 'c' * 40 + '\n',
            prefix + '[{"uses": "missing/proof-action@' + 'c' * 40 + '"}]\n',
            prefix + '[{uses: "./local-action"}]\n',
            prefix + '[{uses: "${{ inputs.action }}"}]\n',
            prefix + '[{run: "curl https://example.invalid/tool", shell: bash}]\n',
            prefix + '[{run: "printf owned && curl missing", shell: bash}]\n',
            prefix + '[{run: "printf $(curl missing)", shell: bash}]\n',
            prefix + '[{run: "printf `curl missing`", shell: bash}]\n',
            prefix + '[{run: "printf \'${{ inputs.command }}\'", shell: bash}]\n',
            prefix + '[{run: "printf owned", run: "curl missing", shell: bash}]\n',
            prefix + '[&step {run: "printf owned", shell: bash}, *step]\n',
            prefix + '[{run: "node main.js", shell: bash}]\n',
            prefix + '\n    - run: |\n        printf owned \\\n        continuation\n      shell: bash\n',
            'name: owned\nruns: {using: node24, main: main.js}\n',
        ]
        for metadata in unsupported:
            with self.subTest(unsupported=metadata):
                self.assertEqual(evaluate(metadata), 'fail')
        self.assertEqual(evaluate(prefix + '[]\n', alternate=True), 'fail')
        with patch.object(security_inventory, '_parse_inventory_yaml', side_effect=security_inventory._YamlError(
                'yaml-parser-unavailable', 'owned missing parser contrast')):
            self.assertEqual(evaluate(prefix + '[]\n'), 'fail')
