"""Deployment observations are bounded consistency checks, never execution grants."""
from __future__ import annotations

import copy
import dataclasses
import hashlib
import importlib.util
import io
import json
import os
import socket
import subprocess
import sys
import tempfile
import unittest
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla import deploy_preflight as preflight
from getzilla import fsx
from getzilla.component_state import BoundRoot


def manifest() -> dict:
    revision = {'label': 'fixture-v1', 'git': None}
    return {
        'schema_version': 'getzilla-deploy-preflight-v1',
        'project_id': 'example',
        'operation': 'dev-delivery',
        'operator': {'path': 'deploy/operator.py', 'sha256': hashlib.sha256(b'operator\n').hexdigest(),
                     'mode': 0o644, 'revision': revision},
        'artifacts': [{'path': 'public/application.js', 'sha256': hashlib.sha256(b'payload\n').hexdigest(),
                       'mode': 0o644}],
        'artifact_revision': copy.deepcopy(revision),
        'target': {'identity': 'dev-example', 'destination_id': 'web-assets', 'transport': 'local-fixture'},
        'credential_selector': '.env.fixture',
        'recovery': {'protocol_id': 'fixture-only', 'version': 'v1', 'descriptor_sha256': 'a' * 64},
    }


def encoded(value: dict) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(',', ':')).encode()


class ManifestTests(unittest.TestCase):
    def rejected(self, raw: bytes, code: str = 'INPUT_INVALID') -> None:
        with self.assertRaises(preflight.PreflightError) as caught:
            preflight.parse_manifest(raw)
        self.assertEqual(caught.exception.code, code)
        self.assertEqual(str(caught.exception), code)

    def test_valid_manifest_is_immutable_and_repr_hides_input(self) -> None:
        parsed = preflight.parse_manifest(encoded(manifest()))
        self.assertIs(type(parsed), preflight.DeployManifest)
        self.assertIs(type(parsed.artifacts), tuple)
        self.assertEqual(parsed.operator.path, 'deploy/operator.py')
        with self.assertRaises(AttributeError):
            parsed.project_id = 'changed'
        for item in (parsed, parsed.operator, *parsed.artifacts):
            self.assertNotIn('.env.fixture', repr(item))
            self.assertNotIn('operator.py', repr(item))

    def test_unknown_and_missing_keys_are_rejected_at_every_object(self) -> None:
        for key in manifest():
            value = manifest()
            del value[key]
            with self.subTest(missing=key):
                self.rejected(encoded(value))
        locations = [(), ('operator',), ('operator', 'revision'), ('artifact_revision',),
                     ('target',), ('recovery',), ('artifacts', 0)]
        for location in locations:
            value = manifest()
            target = value
            for key in location:
                target = target[key]
            target['unexpected'] = 'private-value-must-not-escape'
            with self.subTest(extra=location):
                self.rejected(encoded(value))

    def test_json_duplicates_invalid_utf8_and_noninteger_numbers(self) -> None:
        good = encoded(manifest())
        self.rejected(good.replace(b'"project_id":"example"', b'"project_id":"x","project_id":"example"'))
        self.rejected(good.replace(b'"mode":420', b'"mode":420,"mode":420', 1))
        self.rejected(b'\xff')
        for token in (b'NaN', b'Infinity', b'-Infinity', b'420.0', b'4.2e2', b'true', b'null', b'"420"'):
            with self.subTest(token=token):
                self.rejected(good.replace(b'"mode":420', b'"mode":' + token, 1))
        for value in (None, [], 'private-value-must-not-escape', 1, True):
            self.rejected(json.dumps(value).encode())

    def test_size_depth_and_collection_bounds(self) -> None:
        self.rejected(b' ' * (65536 + 1), 'INPUT_TOO_LARGE')
        self.rejected(b'[' * 2000 + b'0' + b']' * 2000)
        for count in (0, 129):
            value = manifest()
            value['artifacts'] = [dict(value['artifacts'][0], path=f'public/a{i}.js') for i in range(count)]
            self.rejected(encoded(value))
        value = manifest()
        value['artifacts'] = [dict(value['artifacts'][0], path=f'public/a{i}.js') for i in range(128)]
        self.assertEqual(len(preflight.parse_manifest(encoded(value)).artifacts), 128)

    def test_scalar_constraints_and_modes(self) -> None:
        invalids = [
            ('project_id', ''), ('project_id', '../bad'), ('project_id', 'é'), ('project_id', 'a' * 65),
            ('schema_version', 'v2'), ('operation', 'production'),
            ('credential_selector', ''), ('credential_selector', 'x' * 4097),
            ('credential_selector', 'x\nprivate-value'), ('credential_selector', 'x\x7f'),
        ]
        for key, invalid in invalids:
            value = manifest()
            value[key] = invalid
            with self.subTest(key=key, invalid=invalid[:40]):
                self.rejected(encoded(value))
        for key, invalid in [('mode', -1), ('mode', 512), ('sha256', 'A' * 64), ('sha256', 'a' * 63)]:
            value = manifest()
            value['operator'][key] = invalid
            self.rejected(encoded(value))
        for mode in (0, 511):
            value = manifest()
            value['operator']['mode'] = mode
            self.assertEqual(preflight.parse_manifest(encoded(value)).operator.mode, mode)

    def test_revision_oids_are_bounded_declarations(self) -> None:
        for fmt, size in [('sha1', 40), ('sha256', 64)]:
            value = manifest()
            value['artifact_revision']['git'] = {'object_format': fmt, 'commit_oid': 'a' * size,
                                                'tree_oid': 'b' * size}
            preflight.parse_manifest(encoded(value))
            for key, bad in [('commit_oid', 'a' * (size - 1)), ('tree_oid', 'G' * size),
                             ('object_format', 'unknown'), ('other', 'value')]:
                broken = copy.deepcopy(value)
                broken['artifact_revision']['git'][key] = bad
                self.rejected(encoded(broken))

    def test_paths_refuse_traversal_devices_sensitive_inputs_and_collisions(self) -> None:
        invalids = ['', '/absolute', '../outside', 'a/../b', 'a/./b', 'a//b', 'a\\b', 'C:drive',
                    'a/nul.txt', 'a/CON', 'a/trailing.', 'a/trailing ', 'a\x00b', 'a\x7fb',
                    '.git/config', 'x/.GIT/HEAD', '.env.example', 'x/private.pem',
                    'x/credentials.json', 'x/.ssh/id.pub', 'private.db', 'bundle.zip',
                    '/'.join(['a'] * 33), 'a' * 1025]
        for path in invalids:
            value = manifest()
            value['operator']['path'] = path
            with self.subTest(path=path[:60]):
                self.rejected(encoded(value), 'PATH_UNSAFE')
        for path in ('deploy/operator.py', 'DEPLOY/OPERATOR.PY', '.getzilla/config/project-policy.json',
                     'deploy/operator.py/child'):
            value = manifest()
            value['artifacts'][0]['path'] = path
            with self.subTest(collision=path):
                self.rejected(encoded(value), 'PATH_UNSAFE')

    def test_schema_matches_structural_parser_boundaries(self) -> None:
        import jsonschema
        schema = json.loads((ROOT / 'schemas/deploy-preflight-manifest-v1.schema.json').read_text())
        validator = jsonschema.Draft202012Validator(schema)
        validator.check_schema(schema)
        value = manifest()
        self.assertFalse(list(validator.iter_errors(value)))
        variants = []
        for key in value:
            bad = manifest()
            del bad[key]
            variants.append(bad)
        for key, bad_value in [('mode', True), ('mode', 512), ('mode', -1), ('sha256', 'x')]:
            bad = manifest()
            bad['operator'][key] = bad_value
            variants.append(bad)
        bad = manifest()
        bad['target']['extra'] = 'x'
        variants.append(bad)
        for bad in variants:
            self.assertTrue(list(validator.iter_errors(bad)))
            self.rejected(encoded(bad))


@unittest.skipIf(os.name == 'nt', 'POSIX mode observation; Windows refusal has its own control')
class ObservationTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.value = manifest()
        (self.root / 'deploy').mkdir()
        (self.root / 'public').mkdir()
        (self.root / '.getzilla/config').mkdir(parents=True)
        (self.root / 'deploy/operator.py').write_bytes(b'operator\n')
        (self.root / 'public/application.js').write_bytes(b'payload\n')
        (self.root / 'deploy/operator.py').chmod(0o644)
        (self.root / 'public/application.js').chmod(0o644)
        self.policy = {'secret_consumers': [{'script': 'deploy/operator.py', 'secrets': ['.env.fixture']}]}
        self.save()

    def save(self) -> None:
        (self.root / 'fixture.json').write_bytes(encoded(self.value))
        (self.root / preflight.POLICY_PATH).write_bytes(encoded(self.policy))

    def prepare(self):
        return preflight.prepare_preflight(self.root, 'fixture.json')

    def report(self, observation=None):
        if observation is None:
            observation = self.prepare()
        return preflight.recheck_preflight(self.root, observation, 'fixture.json').to_dict()

    def assert_blocked(self, report, code):
        self.assertEqual(report['state'], 'blocked')
        self.assertIn(code, report['diagnostics'])
        self.assertIs(report['dispatch_permitted'], False)
        self.assertIs(report['operational_grant'], False)

    def test_unchanged_observation_is_reviewable_only(self) -> None:
        observation = self.prepare()
        report = self.report(observation)
        self.assertEqual(report['state'], 'ready_for_review')
        self.assertEqual(report['package'], 'matched')
        self.assertEqual(report['registration'], 'matched')
        self.assertEqual(report['provenance'], 'unverified')
        self.assertEqual(report['recovery'], 'declared_unverified')
        self.assertEqual(report['connection'], 'not_attempted')
        self.assertEqual(report['delivery'], 'not_attempted')
        self.assertIs(report['dispatch_permitted'], False)
        self.assertIs(report['operational_grant'], False)
        self.assertEqual(report['expires_at'] - report['issued_at'], 300)
        self.assertEqual(set(report['diagnostics']), {'PROVENANCE_UNVERIFIED', 'RECOVERY_UNVERIFIED'})
        for item in (observation, preflight.recheck_preflight(self.root, observation, 'fixture.json')):
            self.assertNotIn('.env.fixture', repr(item))
        for private in (str(self.root), 'operator.py', '.env.fixture', 'dev-example'):
            self.assertNotIn(private, json.dumps(report))

    def test_same_registered_operator_path_does_not_authorize_replacement(self) -> None:
        observation = self.prepare()
        (self.root / 'deploy/operator.py').write_bytes(b'changed operator\n')
        self.assert_blocked(self.report(observation), 'HASH_MISMATCH')

    def test_artifact_bytes_modes_and_identity_are_bound(self) -> None:
        artifact = self.root / 'public/application.js'
        for mutation, code in [('bytes', 'HASH_MISMATCH'), ('mode', 'MODE_MISMATCH'), ('replace', 'OBSERVATION_CHANGED')]:
            with self.subTest(mutation=mutation):
                artifact.write_bytes(b'payload\n')
                artifact.chmod(0o644)
                observation = self.prepare()
                if mutation == 'bytes':
                    artifact.write_bytes(b'changed\n')
                elif mutation == 'mode':
                    artifact.chmod(0o600)
                else:
                    artifact.unlink()
                    artifact.write_bytes(b'payload\n')
                    artifact.chmod(0o644)
                self.assert_blocked(self.report(observation), code)

    def test_manifest_target_selector_recovery_and_revisions_invalidate_binding(self) -> None:
        edits = [('target', 'identity', 'different'), ('target', 'destination_id', 'other'),
                 ('target', 'transport', 'ssh-sftp'), ('recovery', 'version', 'v2'),
                 ('recovery', 'descriptor_sha256', 'b' * 64), ('artifact_revision', 'label', 'v2'),
                 ('operator', 'revision', {'label': 'v2', 'git': None})]
        for group, key, value in edits:
            self.value = manifest()
            self.save()
            observation = self.prepare()
            self.value[group][key] = value
            (self.root / 'fixture.json').write_bytes(encoded(self.value))
            with self.subTest(group=group, key=key):
                self.assert_blocked(self.report(observation), 'OBSERVATION_CHANGED')
        self.value = manifest()
        self.save()
        observation = self.prepare()
        self.value['credential_selector'] = '.env.other'
        self.policy['secret_consumers'][0]['secrets'].append('.env.other')
        self.save()
        self.assert_blocked(self.report(observation), 'OBSERVATION_CHANGED')
        self.value['operation'] = 'production'
        self.save()
        self.assert_blocked(self.report(observation), 'INPUT_INVALID')

    def test_policy_changes_revoke_or_invalidate_observation(self) -> None:
        observation = self.prepare()
        self.policy['secret_consumers'] = []
        (self.root / preflight.POLICY_PATH).write_bytes(encoded(self.policy))
        self.assert_blocked(self.report(observation), 'OBSERVATION_CHANGED')
        fresh = self.report()
        self.assert_blocked(fresh, 'CONSUMER_UNREGISTERED')
        self.assertEqual(fresh['registration'], 'missing')
        self.assertEqual(fresh['package'], 'matched')
        policy = self.root / preflight.POLICY_PATH
        policy.unlink()
        self.assert_blocked(self.report(observation), 'POLICY_MISSING')
        for invalid in (b'{', b'{}', b'{"secret_consumers":[],"secret_consumers":[]}',
                        b'{"secret_consumers":[{"script":"x","secrets":3}]}'):
            policy.write_bytes(invalid)
            self.assert_blocked(self.report(observation), 'POLICY_INVALID')

    def test_exact_policy_bytes_are_bound_even_when_registration_is_unchanged(self) -> None:
        observation = self.prepare()
        self.policy['unrelated_metadata'] = 'different'
        (self.root / preflight.POLICY_PATH).write_bytes(encoded(self.policy))
        self.assert_blocked(self.report(observation), 'OBSERVATION_CHANGED')

    def test_policy_metadata_is_allowed_but_bounded(self) -> None:
        self.policy['unrelated'] = {'cost': 0.25, 'enabled': True}
        self.policy['secret_consumers'][0]['owner_metadata'] = {'reviewed': True}
        self.save()
        self.assertEqual(self.report()['registration'], 'matched')
        for key, value in [('script', ''), ('script', 'x' * 4097), ('secrets', ['x'] * 65),
                           ('secrets', ['']), ('secrets', ['x' * 4097]), ('secrets', [False])]:
            self.policy['secret_consumers'] = [{'script': 'deploy/operator.py', 'secrets': ['.env.fixture']}]
            self.policy['secret_consumers'][0][key] = value
            self.save()
            with self.assertRaises(preflight.PreflightError) as error:
                self.prepare()
            self.assertEqual(error.exception.code, 'POLICY_INVALID')

    def test_manifest_alias_is_rejected_before_manifest_read(self) -> None:
        aliases = ['fixture.json', './fixture.json', 'part/../fixture.json', '.\\fixture.json',
                   'FIXTURE.JSON', str(self.root / 'fixture.json'), str(self.root / './fixture.json'),
                   '.', str(self.root), '$UNKNOWN/file', '~/file', 'C:relative', 'https://host/selector',
                   '//server/share', 'prefix/*']
        original = BoundRoot.read
        for alias in aliases:
            self.policy['secret_consumers'][0]['secrets'] = [alias]
            self.save()
            calls = []
            def observe(binding, relative, **kwargs):
                calls.append(relative)
                return original(binding, relative, **kwargs)
            with patch.object(BoundRoot, 'read', observe), self.assertRaises(preflight.PreflightError) as error:
                self.prepare()
            with self.subTest(alias=alias):
                self.assertEqual(error.exception.code, 'PATH_UNSAFE')
                self.assertEqual(calls, [preflight.POLICY_PATH])

    def test_entire_inventory_is_admitted_before_any_payload_open(self) -> None:
        original = BoundRoot.read
        for selector in ['public', 'public/application.js', 'PUBLIC/APPLICATION.JS',
                         'public/application.js/descendant', str(self.root / 'public/application.js')]:
            self.value['credential_selector'] = selector
            self.save()
            calls = []
            def observe(binding, relative, **kwargs):
                calls.append(relative)
                return original(binding, relative, **kwargs)
            with patch.object(BoundRoot, 'read', observe), self.assertRaises(preflight.PreflightError) as error:
                self.prepare()
            self.assertEqual(error.exception.code, 'PATH_UNSAFE')
            self.assertEqual(calls, [preflight.POLICY_PATH, 'fixture.json'])

    def test_nonmatching_policy_selectors_still_exclude_reads(self) -> None:
        self.policy['secret_consumers'].append({'script': '/outside/uninspected.py',
                                              'secrets': ['public/application.js']})
        self.save()
        with self.assertRaises(preflight.PreflightError) as error:
            self.prepare()
        self.assertEqual(error.exception.code, 'PATH_UNSAFE')

    def test_outside_or_nonportable_script_cannot_match_or_be_inspected(self) -> None:
        for script in ['/outside/operator.py', '../operator.py', str(self.root / 'deploy/operator.py'),
                       './deploy/operator.py', 'DEPLOY/OPERATOR.PY']:
            self.policy['secret_consumers'][0]['script'] = script
            self.save()
            with patch('os.path.realpath', side_effect=AssertionError('private-path')), \
                    patch.object(Path, 'resolve', side_effect=AssertionError('private-path')):
                report = self.report()
            self.assert_blocked(report, 'CONSUMER_UNREGISTERED')

    def test_links_hardlinks_special_files_and_unsafe_root_fail(self) -> None:
        artifact = self.root / 'public/application.js'
        artifact.unlink()
        artifact.symlink_to(self.root / 'deploy/operator.py')
        with self.assertRaises(preflight.PreflightError) as error:
            self.prepare()
        self.assertEqual(error.exception.code, 'FILE_UNSAFE')
        artifact.unlink()
        os.link(self.root / 'deploy/operator.py', artifact)
        with self.assertRaises(preflight.PreflightError) as error:
            self.prepare()
        self.assertEqual(error.exception.code, 'FILE_UNSAFE')
        artifact.unlink()
        os.mkfifo(artifact)
        with self.assertRaises(preflight.PreflightError) as error:
            self.prepare()
        self.assertEqual(error.exception.code, 'FILE_UNSAFE')
        artifact.unlink()
        artifact.write_bytes(b'payload\n')
        alias = self.root / 'alias'
        alias.symlink_to(self.root, target_is_directory=True)
        # Root-owned system links may be canonicalized; this is an untrusted parent.
        self.root.chmod(0o777)
        with self.assertRaises(preflight.PreflightError) as error:
            preflight.prepare_preflight(alias, 'fixture.json')
        self.assertEqual(error.exception.code, 'ROOT_CHANGED')

    def test_other_root_or_manifest_spelling_rejects_old_observation(self) -> None:
        observation = self.prepare()
        with tempfile.TemporaryDirectory() as empty:
            report = preflight.recheck_preflight(Path(empty), observation, 'fixture.json').to_dict()
        self.assert_blocked(report, 'ROOT_CHANGED')
        self.assert_blocked(preflight.recheck_preflight(self.root, observation, './fixture.json').to_dict(), 'PATH_UNSAFE')
        (self.root / 'second.json').write_bytes(encoded(self.value))
        self.assert_blocked(preflight.recheck_preflight(self.root, observation, 'second.json').to_dict(), 'OBSERVATION_CHANGED')

    def test_later_payload_mutation_is_detected_by_second_pass(self) -> None:
        original = BoundRoot.read
        seen = []
        def mutate(binding, relative, **kwargs):
            snapshot = original(binding, relative, **kwargs)
            seen.append(relative)
            if relative == 'public/application.js' and seen.count(relative) == 1:
                (self.root / 'deploy/operator.py').write_bytes(b'changed after first read\n')
            return snapshot
        with patch.object(BoundRoot, 'read', mutate), self.assertRaises(preflight.PreflightError) as error:
            self.prepare()
        self.assertEqual(error.exception.code, 'FILE_CHANGED')
        self.assertEqual(seen.count('deploy/operator.py'), 2)

    def test_policy_change_stops_second_pass_before_new_manifest_or_payload_reads(self) -> None:
        original = BoundRoot.read
        calls = []
        def mutate(binding, relative, **kwargs):
            snapshot = original(binding, relative, **kwargs)
            calls.append(relative)
            if relative == 'public/application.js':
                (self.root / preflight.POLICY_PATH).write_bytes(b'{"secret_consumers":[]}')
            return snapshot
        with patch.object(BoundRoot, 'read', mutate), self.assertRaises(preflight.PreflightError) as error:
            self.prepare()
        self.assertEqual(error.exception.code, 'FILE_CHANGED')
        self.assertEqual(calls[-1], preflight.POLICY_PATH)
        self.assertEqual(calls.count('fixture.json'), 1)

    def test_expiry_clock_and_implementation_revision_are_checked(self) -> None:
        with patch.object(preflight.time, 'time', return_value=1000.0):
            observation = self.prepare()
        for clock, code in [(999.0, 'CLOCK_UNCERTAIN'), (1300.0, 'OBSERVATION_EXPIRED'),
                            (float('nan'), 'CLOCK_UNCERTAIN'), (float('inf'), 'CLOCK_UNCERTAIN'),
                            (True, 'CLOCK_UNCERTAIN')]:
            with patch.object(preflight.time, 'time', return_value=clock):
                self.assert_blocked(self.report(observation), code)
        with patch.object(preflight.time, 'time', return_value=1299.0):
            self.assertEqual(self.report(observation)['state'], 'ready_for_review')
        for name in ('ALGORITHM_REVISION', 'SCHEMA_REVISION'):
            with patch.object(preflight, name, 'different'):
                self.assert_blocked(self.report(observation), 'ALGORITHM_CHANGED')

    def test_typed_observation_cannot_be_replayed_or_tampered_with(self) -> None:
        observation = self.prepare()
        for value in [dataclasses.asdict(observation), None, True,
                      dataclasses.replace(observation, root_identity=(True, 2, 3)),
                      dataclasses.replace(observation, issued_at=True),
                      dataclasses.replace(observation, registration='private-value')]:
            self.assert_blocked(preflight.recheck_preflight(self.root, value, 'fixture.json').to_dict(), 'INPUT_INVALID')
        changed = dataclasses.replace(observation, digest='f' * 64)
        self.assert_blocked(self.report(changed), 'OBSERVATION_CHANGED')

    def test_report_rejects_untrusted_fields_and_has_a_closed_output(self) -> None:
        report = preflight.recheck_preflight(self.root, self.prepare(), 'fixture.json')
        changed = dataclasses.replace(report, diagnostics=('synthetic-private-value',))
        safe = changed.to_dict()
        self.assert_blocked(safe, 'INTERNAL_ERROR')
        self.assertNotIn('synthetic-private-value', json.dumps(safe))
        self.assertEqual(set(safe), {'schema_version', 'state', 'observation_digest', 'issued_at', 'expires_at',
                                    'package', 'registration', 'provenance', 'recovery', 'connection', 'delivery',
                                    'dispatch_permitted', 'operational_grant', 'diagnostics'})

    def test_rebuilt_hashes_and_declared_oids_never_prove_provenance_or_recovery(self) -> None:
        (self.root / 'deploy/operator.py').write_bytes(b'new unreviewed bytes\n')
        self.value['operator']['sha256'] = hashlib.sha256(b'new unreviewed bytes\n').hexdigest()
        self.value['operator']['revision']['git'] = {'object_format': 'sha1', 'commit_oid': 'a' * 40, 'tree_oid': 'b' * 40}
        self.value['recovery']['protocol_id'] = 'unknown-live-legacy-owner'
        self.save()
        report = self.report()
        self.assertEqual(report['state'], 'ready_for_review')
        self.assertEqual(report['provenance'], 'unverified')
        self.assertEqual(report['recovery'], 'declared_unverified')
        self.assertIs(report['dispatch_permitted'], False)

    def test_no_writes_network_dispatch_private_reads_or_module_file_access(self) -> None:
        before = {p.relative_to(self.root).as_posix(): p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        original = fsx.open_at
        admitted = {'project-policy.json', 'fixture.json', 'operator.py', 'application.js'}
        opened = []
        def read_only(parent, name, flags, *args, **kwargs):
            self.assertIn(name, admitted)
            self.assertEqual(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND), 0)
            opened.append(name)
            return original(parent, name, flags, *args, **kwargs)
        with ExitStack() as stack:
            for owner, name in [(socket, 'socket'), (subprocess, 'Popen'), (os, 'system'),
                                (os, 'unlink'), (os, 'mkdir'), (os, 'rename'), (os, 'replace'),
                                (Path, 'read_bytes'), (Path, 'read_text'), (Path, 'write_bytes'), (Path, 'write_text')]:
                stack.enter_context(patch.object(owner, name, side_effect=AssertionError('forbidden-private-value')))
            stack.enter_context(patch.object(fsx, 'open_at', read_only))
            stack.enter_context(patch.object(preflight, '__file__', '/unavailable/engine.zip/getzilla/deploy_preflight.py'))
            report = self.report()
        self.assertEqual(report['state'], 'ready_for_review')
        self.assertEqual(set(opened), admitted)
        self.assertEqual(len(opened), 16)  # two reads of four files in both prepare and recheck
        after = {p.relative_to(self.root).as_posix(): p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        self.assertEqual(before, after)

    def test_safe_error_output_and_resource_cleanup_on_injected_failure(self) -> None:
        observation = self.prepare()
        original_close = BoundRoot.close
        closed = []
        def close(binding):
            original_close(binding)
            closed.append(binding)
            self.assertFalse(binding._handles)
        with patch.object(BoundRoot, 'read', side_effect=RuntimeError('synthetic-private-value')), \
                patch.object(BoundRoot, 'close', close):
            report = self.report(observation)
        self.assert_blocked(report, 'INTERNAL_ERROR')
        self.assertEqual(len(closed), 1)
        self.assertNotIn('synthetic-private-value', json.dumps(report))
        with patch.object(BoundRoot, 'read', side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.report(observation)

    def test_size_and_monotonic_work_budgets_stop_reads(self) -> None:
        with patch.object(preflight, 'MAX_FILE_BYTES', 4), self.assertRaises(preflight.PreflightError) as error:
            self.prepare()
        self.assertEqual(error.exception.code, 'FILE_UNSAFE')
        with patch.object(preflight, 'MAX_TOTAL_BYTES', 9), self.assertRaises(preflight.PreflightError) as error:
            self.prepare()
        self.assertEqual(error.exception.code, 'INPUT_TOO_LARGE')
        with patch.object(preflight.time, 'monotonic', side_effect=[0.0, 11.0]), \
                patch.object(BoundRoot, 'read') as read, self.assertRaises(preflight.PreflightError) as error:
            self.prepare()
        self.assertEqual(error.exception.code, 'BUDGET_EXCEEDED')
        read.assert_not_called()


class CredentialFloorTests(unittest.TestCase):
    paths = (
        '.codex/auth.json', '.CODEX/AUTH.JSON', 'nested/.codex/auth.json',
        '.claude/.credentials.json', '.vault-token', '.config/gh/hosts.yml', '.config/gh/opaque',
        '.config/gh', '.composer/auth.json', '.config/composer/auth.json',
        '.config/gcloud/opaque', '.azure/opaque', '.terraform.d/credentials.tfrc.json',
        '.cargo/credentials.toml', '.gem/credentials', 'credentials.other', 'nested/credentials-data',
        'secrets/opaque.txt', 'nested/secrets/opaque.txt', 'trust-ci/runtime/opaque',
        '.codex/auth.json/child', '.env.example', '.ssh/known_hosts',
    )

    def test_manifest_is_rejected_before_any_bound_input_read(self) -> None:
        for path in self.paths:
            with self.subTest(path=path), patch.object(BoundRoot, 'read') as read:
                with self.assertRaises(preflight.PreflightError) as error:
                    preflight.prepare_preflight(ROOT, path)
                self.assertEqual(error.exception.code, 'PATH_UNSAFE')
                read.assert_not_called()

    def test_operator_and_artifacts_reject_the_same_credential_floor(self) -> None:
        for path in self.paths:
            for role in ('operator', 'artifact'):
                value = manifest()
                target = value['operator'] if role == 'operator' else value['artifacts'][0]
                target['path'] = path
                with self.subTest(path=path, role=role):
                    with self.assertRaises(preflight.PreflightError) as error:
                        preflight.parse_manifest(encoded(value))
                    self.assertEqual(error.exception.code, 'PATH_UNSAFE')


class PlatformTests(unittest.TestCase):
    def test_windows_refuses_posix_mode_claim_before_any_input_open(self) -> None:
        with patch.object(preflight.fsx, 'WINDOWS', True), patch.object(preflight, 'BoundRoot') as reader:
            with self.assertRaises(preflight.PreflightError) as error:
                preflight.prepare_preflight(Path('/uninspected'), 'fixture.json')
        self.assertEqual(error.exception.code, 'MODE_UNSUPPORTED')
        reader.assert_not_called()


class CliTests(unittest.TestCase):
    def load_cli(self):
        spec = importlib.util.spec_from_file_location('deploy_cli_fixture', ROOT / 'scripts/getzilla_deploy.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def invoke(self, module, args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = module.main(args)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_import_is_safe_and_legacy_flat_arguments_are_preserved(self) -> None:
        with patch('getzilla.deploy.prepare_deploy', side_effect=AssertionError('import side effect')):
            module = self.load_cli()
        for args, record in [([], False), (['--json'], False), (['--record', '--json'], True)]:
            with patch.object(module, 'find_root', return_value=Path('/fixture-root')) as find, \
                    patch.object(module, 'prepare_deploy', return_value={'ok': True, 'commands': ['fixture-command']}) as prepare:
                code, stdout, stderr = self.invoke(module, args)
            self.assertEqual(code, 0, stderr)
            self.assertIn('fixture-command', stdout)
            find.assert_called_once_with()
            prepare.assert_called_once_with(Path('/fixture-root'), record=record)

    def test_preflight_rejects_bad_arguments_without_echo_or_input_read(self) -> None:
        module = self.load_cli()
        for args in [[], ['--root', '/fixture'], ['--manifest', 'fixture.json'],
                     ['--root', '/fixture', '--manifest', 'fixture.json', '--record'],
                     ['--root', '/fixture', '--manifest', 'fixture.json', 'synthetic-private-value'],
                     ['--root', '/fixture', '--manifest', 'fixture.json', '--unknown=synthetic-private-value']]:
            with patch.object(preflight, 'prepare_preflight', side_effect=AssertionError('input read')), \
                    patch.object(module, 'prepare_deploy', side_effect=AssertionError('release effect')), \
                    patch.object(module, 'find_root', side_effect=AssertionError('root discovery')):
                code, stdout, stderr = self.invoke(module, ['preflight', *args])
            self.assertEqual(code, 2)
            self.assertEqual(stdout, '')
            self.assertEqual(stderr, 'getzilla deploy preflight: invalid arguments\n')

    def test_help_is_static_and_preflight_failures_have_safe_json(self) -> None:
        module = self.load_cli()
        stdout = io.StringIO()
        with redirect_stdout(stdout), self.assertRaises(SystemExit) as exit_status:
            module.main(['preflight', '--help'])
        self.assertEqual(exit_status.exception.code, 0)
        self.assertIn('--root', stdout.getvalue())
        with patch.object(preflight, 'prepare_preflight', side_effect=preflight.PreflightError('HASH_MISMATCH')), \
                patch.object(module, 'prepare_deploy', side_effect=AssertionError('release effect')), \
                patch.object(module, 'find_root', side_effect=AssertionError('root discovery')):
            code, stdout, stderr = self.invoke(module, ['preflight', '--root', '/fixture', '--manifest', 'fixture.json', '--json'])
        self.assertEqual(code, 1)
        self.assertEqual(stderr, '')
        self.assertIn('HASH_MISMATCH', json.loads(stdout)['diagnostics'])

    def test_installed_files_and_zip_engines_from_root_and_subdirectory(self) -> None:
        from tests.test_install_on_demand import INSTALL
        environment = {key: value for key, value in os.environ.items()
                       if key not in {'PYTHONPATH', 'PYTHONDONTWRITEBYTECODE', 'PYTHONPYCACHEPREFIX'}}
        with tempfile.TemporaryDirectory() as directory:
            for archive in (False, True):
                with self.subTest(archive=archive):
                    target = Path(directory) / ('archive' if archive else 'files')
                    INSTALL._materialize_new(ROOT, target, include_dependencies=False, include_optional=False,
                                             selection=INSTALL.PayloadSelection((), engine_archive=archive))
                    for relative in ('schemas/deploy-preflight-manifest-v1.schema.json', 'docs/deploy-preflight.md'):
                        self.assertEqual((target / relative).read_bytes(), (ROOT / relative).read_bytes())
                    if archive:
                        self.assertFalse((target / '.getzilla/getzilla/deploy_preflight.py').exists())
                    else:
                        self.assertTrue((target / '.getzilla/getzilla/deploy_preflight.py').is_file())
                    (target / 'deploy').mkdir()
                    (target / 'public').mkdir()
                    (target / 'deploy/operator.py').write_bytes(b'operator\n')
                    (target / 'public/application.js').write_bytes(b'payload\n')
                    for relative in ('deploy/operator.py', 'public/application.js'):
                        (target / relative).chmod(0o644)
                    (target / preflight.POLICY_PATH).write_bytes(encoded({'secret_consumers': [
                        {'script': 'deploy/operator.py', 'secrets': ['.env.fixture']}]}))
                    (target / 'fixture.json').write_bytes(encoded(manifest()))
                    nested = target / 'src/deep'
                    nested.mkdir(parents=True)
                    (nested / 'fixture.json').write_bytes(b'not the explicit root input')
                    def snapshot():
                        return {p.relative_to(target).as_posix():
                                (p.stat().st_mode, hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None)
                                for p in target.rglob('*')}
                    before = snapshot()
                    for cwd, script, prefix in [(target, target / 'scripts/getzilla_deploy.py', []),
                                                (nested, ROOT / 'scripts/getzilla_cli.py', ['deploy'])]:
                        # -I removes checkout imports and ignores bytecode environment settings;
                        # deliberately no -B, so accidental import-cache writes are observable.
                        result = subprocess.run([sys.executable, '-I', str(script), *prefix, 'preflight',
                                                 '--root', str(target), '--manifest', 'fixture.json', '--json'],
                                                cwd=cwd, env=environment, capture_output=True, text=True, timeout=30)
                        self.assertEqual(result.stderr, '')
                        report = json.loads(result.stdout)
                        if os.name == 'nt':
                            self.assertEqual(result.returncode, 1)
                            self.assertIn('MODE_UNSUPPORTED', report['diagnostics'])
                        else:
                            self.assertEqual(result.returncode, 0, result.stdout)
                            self.assertEqual(report['state'], 'ready_for_review')
                        self.assertIs(report['dispatch_permitted'], False)
                        self.assertEqual(report['provenance'], 'unverified')
                        self.assertEqual(snapshot(), before, 'preflight must not create caches, native state or locks')


if __name__ == '__main__':
    unittest.main()
