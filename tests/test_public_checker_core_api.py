"""New Core API controls. All data/effects belong to one inert private fixture.

No retained test helpers, project inventory, scanner, daemon or network runs.
The I/O guard allows owned fixture bytes and directory traversal to those bytes.
"""
from __future__ import annotations

import builtins
import copy
import ctypes
from contextlib import ExitStack, contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import yaml  # Load the qualified syntax reader before closing fixture I/O.
from getzilla import expanded_security as expanded
from getzilla import security_cli as cli
from getzilla import security_inventory as inventory
from getzilla import security_oci as oci
from getzilla import security_tools as tools
from getzilla.security_data import SecurityDataError

NOW = datetime(2026, 11, 17, tzinfo=timezone.utc)
PROJECT = Path(__file__).resolve().parents[1]
SERVICE = 'owned/service@sha256:' + 'a' * 64
RUNNER = 'owned/runner@sha256:' + 'b' * 64


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def sha(value):
    return hashlib.sha256(value).hexdigest()


def source():
    return dict(head_sha='1' * 40, tree_sha='2' * 40, checker_sha='3' * 40,
                checker_tree_sha='4' * 40, candidate_clean=True, checker_clean=True, same_project=True)


def context():
    return dict(kind='getzilla-public-execution-v1', repository='owned/project', repository_id=1,
                pr_number=2, base_sha='0' * 40, **{k: v for k, v in source().items() if k.endswith('sha')},
                runner_repository='owned/checker', runner_repository_id=3, runner_sha='5' * 40,
                runner_tree_sha='6' * 40, workflow_id=4, workflow_blob_sha='7' * 40, run_id=5, run_attempt=1)


@contextmanager
def fixture_guard(base):
    """Deny outside bytes, subprocesses, native loads and network effects."""
    real_open, real_io, real_os = builtins.open, io.open, os.open
    root = base.resolve()

    def target(path, dir_fd=None):
        if isinstance(path, int):
            return Path(os.readlink('/proc/self/fd/' + str(path))).resolve()
        value = Path(os.fsdecode(path))
        if not value.is_absolute() and dir_fd is not None:
            value = Path(os.readlink('/proc/self/fd/' + str(dir_fd))) / value
        return value.resolve()

    def check(path, *, directory=False, dir_fd=None):
        value = target(path, dir_fd)
        if not value.is_relative_to(root) and not (directory and root.is_relative_to(value)):
            raise AssertionError('outside-fixture I/O denied')

    def guarded_open(path, *args, **kwargs):
        check(path)
        return real_open(path, *args, **kwargs)

    def guarded_io(path, *args, **kwargs):
        check(path)
        return real_io(path, *args, **kwargs)

    def guarded_os(path, flags, *args, **kwargs):
        check(path, directory=bool(flags & os.O_DIRECTORY), dir_fd=kwargs.get('dir_fd'))
        return real_os(path, flags, *args, **kwargs)

    def listing(function):
        def guarded(path='.'):
            check(path)
            return function(path)
        return guarded

    def deny(*args, **kwargs):
        raise AssertionError('unmocked process/native/network effect denied')

    with ExitStack() as stack:
        stack.enter_context(patch('builtins.open', guarded_open))
        stack.enter_context(patch('io.open', guarded_io))
        stack.enter_context(patch('os.open', guarded_os))
        # Preserve the real platform capability while wrapping its opener.
        stack.enter_context(patch.object(os, 'supports_dir_fd', os.supports_dir_fd | {guarded_os}))
        stack.enter_context(patch.object(os, 'listdir', listing(os.listdir)))
        stack.enter_context(patch.object(os, 'scandir', listing(os.scandir)))
        for module, name in ((subprocess, 'Popen'), (os, 'system'), (os, 'fork'),
                             (os, 'posix_spawn'), (socket, 'socket'), (socket, 'getaddrinfo'),
                             (ctypes, 'CDLL'), (ctypes, 'PyDLL')):
            stack.enter_context(patch.object(module, name, deny))
        yield


class CoreApiTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(callable(yaml.parse))
        scratch = PROJECT / '.getzilla/runtime/scratch'
        scratch.mkdir(parents=True, exist_ok=True)
        self.directory = tempfile.TemporaryDirectory(prefix='owned-core-api-', dir=scratch)
        self.addCleanup(self.directory.cleanup)
        self.base = Path(self.directory.name)
        self.root = self.base / 'source'
        self.root.mkdir()
        self.snapshot = self.base / 'snapshot'
        self.snapshot.mkdir()
        self.roots = [self.snapshot / name for name in ('database', 'artifacts', 'tools')]
        for path in self.roots:
            path.mkdir()
        self.guards = ExitStack()
        self.guards.enter_context(fixture_guard(self.base))
        self.guards.enter_context(patch.object(inventory, '_tracked_files', side_effect=self.tracked))
        self.guards.enter_context(patch.object(cli, 'source_binding', side_effect=self.observed_source))
        self.guards.enter_context(patch.object(cli, 'TRUSTED_ROOT', self.root))
        self.guards.enter_context(patch.object(tools, 'TRUSTED_ROOT', self.root))
        self.addCleanup(self.guards.close)

    def tracked(self, root):
        self.assertEqual(Path(root), self.root)
        return sorted(path.relative_to(self.root).as_posix() for path in self.root.rglob('*') if path.is_file())

    def observed_source(self, root, checker, scratch):
        self.assertEqual(Path(root), self.root)
        self.assertEqual(Path(checker), self.root)
        self.assertTrue(Path(scratch).is_relative_to(self.base))
        return source()

    def compose(self, *, form='mapping', dynamic=False):
        service = '${SERVICE_IMAGE}' if dynamic else SERVICE
        runner = '${TRUST_CI_RUNNER_IMAGE:?required}' if dynamic else RUNNER
        environment = ('      TRUST_CI_RUNNER_IMAGE: ' + runner if form == 'mapping'
                       else '      - TRUST_CI_RUNNER_IMAGE=' + runner)
        body = ('services:\n  worker:\n    platform: linux/amd64\n    image: ' + service +
                '\n    environment:\n' + environment + '\n      UNRELATED: ignored\n' if form == 'mapping' else
                'services:\n  worker:\n    platform: linux/amd64\n    image: ' + service +
                '\n    environment:\n' + environment + '\n      - UNRELATED=ignored\n')
        path = self.root / 'compose.yaml'
        path.write_text(body)
        return [dict(path='compose.yaml', line=line, source_sha256=sha(body.encode()), expression=expression,
                     reference=reference, platform='linux/amd64')
                for line, expression, reference in ((4, service, SERVICE), (6, runner, RUNNER))]

    def require_api(self):
        self.assertTrue(hasattr(cli, 'public_input_scope'), 'public Core scope is missing')
        from getzilla import public_security_context, security_oci
        return public_security_context, security_oci

    def catalog(self):
        rows = self.compose(dynamic=True)
        current = inventory.collect_inventory(self.root, image_bindings=rows)
        catalog = dict(schema_version=1, inventory_sha256=current['digest'], records=[
            dict(reference=ref, platform='linux/amd64', layout=str(self.snapshot / ('layout-' + str(index))))
            for index, ref in enumerate((SERVICE, RUNNER))], source_bindings=[
                dict(manifest=row['path'], line=row['line'], source_sha256=row['source_sha256'],
                     source_reference=row['expression'], reference=row['reference'], platform=row['platform']) for row in rows])
        path = self.snapshot / 'catalog.json'
        path.write_bytes(encoded(catalog))
        return path, catalog

    def test_compose_runner_and_service_exact_source_uses(self):
        for form in ('mapping', 'sequence'):
            with self.subTest(form=form):
                self.compose(form=form)
                current = inventory.collect_inventory(self.root)
                self.assertEqual([row['reference'] for row in current['images']], [SERVICE, RUNNER])
                self.assertTrue(current['complete'], current['gaps'])
                self.assertEqual([row['line'] for row in current['images']], [4, 6])
                self.assertEqual([row['platform'] for row in current['images']], ['linux/amd64'] * 2)

    def test_exact_bindings_reject_drift_duplicates_missing_conflict_and_unused(self):
        self.require_api()
        rows = self.compose(dynamic=True)
        self.assertTrue(inventory.collect_inventory(self.root, image_bindings=rows)['complete'])
        for key, value in (('line', 7), ('source_sha256', 'f' * 64), ('expression', '${OTHER}'),
                           ('path', 'absent.yaml'), ('platform', 'linux/arm64')):
            bad = copy.deepcopy(rows)
            bad[1][key] = value
            with self.subTest(key=key):
                current = inventory.collect_inventory(self.root, image_bindings=bad)
                self.assertFalse(current['complete'])
        self.assertFalse(inventory.collect_inventory(self.root, image_bindings=rows[:1])['complete'])
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            inventory.collect_inventory(self.root, image_bindings=rows + rows[:1])
        extra = dict(rows[1], path='unused.yaml')
        self.assertIn('unused-image-source-selection', {gap['code'] for gap in inventory.collect_inventory(
            self.root, image_bindings=rows + [extra])['gaps']})
        self.compose()
        current = inventory.collect_inventory(self.root)
        pinned_rows = [dict(path=row['manifest'], line=row['line'], source_sha256=row['source_sha256'],
                            expression=row['source_reference'], reference=row['reference'], platform=row['platform'])
                       for row in current['images']]
        self.assertFalse(inventory.collect_inventory(self.root, image_bindings=pinned_rows[:1])['complete'],
                         'literal runner use still requires its own selection')
        pinned_rows[1]['reference'] = SERVICE
        with self.assertRaisesRegex(ValueError, 'conflicts'):
            inventory.collect_inventory(self.root, image_bindings=pinned_rows)

    def test_distinct_runner_authority_and_context_lifetime(self):
        public, _ = self.require_api()
        declared = context()
        run = public.validate_context(declared, source())
        self.assertEqual(run['head_sha'], '5' * 40)
        with self.assertRaises(SecurityDataError):
            cli.validate_selection_authority(source(), run, now=NOW)
        with public.bind_context(declared, source()):
            cli.validate_selection_authority(source(), run, now=NOW)
            detached = public.current_context()
            detached['runner_sha'] = 'f' * 40
            self.assertEqual(public.current_context(), declared)
            with self.assertRaises(SecurityDataError):
                cli.validate_selection_authority(source(), dict(run, head_sha='f' * 40), now=NOW)
            selection = dict(schema_version=1, source=source(), run=run, created_at=(NOW - timedelta(days=4)).isoformat(), uses=[{}])
            with self.assertRaisesRegex(SecurityDataError, 'stale'):
                cli.validate_selection_authority(source(), run, selection, now=NOW)
            for key, value in (('run_id', True), ('runner_sha', 'F' * 40), ('extra', 'x'), ('head_sha', 'f' * 40)):
                with self.subTest(key=key), self.assertRaises(ValueError):
                    public.validate_context(dict(declared, **{key: value}), source())
            with self.assertRaisesRegex(ValueError, 'clean'):
                public.validate_context(declared, dict(source(), candidate_clean=False))
        self.assertIsNone(public.current_context())
        with self.assertRaises(SecurityDataError):
            cli.validate_selection_authority(source(), run, now=NOW)
        native = dict(run, head_sha=source()['head_sha'])
        cli.validate_selection_authority(source(), native, now=NOW)

    def test_public_evaluation_forwards_canonical_inputs(self):
        public, _ = self.require_api()
        path, _ = self.catalog()
        calls = []

        def canonical(root, database, artifacts, selected_tools, **options):
            self.assertEqual((root, database, artifacts, selected_tools), (self.root, *self.roots))
            self.assertFalse(options['refresh'])
            self.assertFalse(options['provision'])
            self.assertEqual(options['run']['head_sha'], context()['runner_sha'])
            self.assertEqual(public.current_context(), context())
            self.assertTrue(options['image_artifacts'].is_file())
            self.assertTrue(options['image_selection'].is_file())
            cli.validate_input_profile(options['profile'], source(), inventory.declared_inventory(
                root, inventory.read_image_selection(options['image_selection'])), dict(zip(
                    ('database', 'artifacts', 'tools'), map(str, self.roots))), options['run'],
                cli._policy_digest(self.root), now=NOW, image_artifacts=json.loads(options['image_artifacts'].read_text()),
                image_selection=inventory.read_image_selection(options['image_selection']))
            calls.append(options)
            return {'status': 'fail', 'qualification_gaps': ['owned-canonical-sentinel']}

        with patch.object(cli, 'evaluate', side_effect=canonical):
            report = cli.evaluate_public(self.root, *self.roots, context=context(), image_artifacts=path, now=NOW)
        self.assertEqual(report['qualification_gaps'], ['owned-canonical-sentinel'])
        self.assertEqual(report['public_inputs']['context'], context())
        self.assertEqual(len(calls), 1)
        self.assertFalse(calls[0]['image_selection'].exists())
        self.assertIsNone(public.current_context())

    def test_public_scope_and_native_selection_consume_owned_closure(self):
        public, _ = self.require_api()
        path, catalog = self.catalog()
        with cli.public_input_scope(self.root, *self.roots, context=context(), image_artifacts=path, now=NOW) as selected:
            self.assertEqual(selected['binding']['source_catalog_sha256'], sha(encoded(catalog)))
            self.assertEqual(expanded.selected_inventory(self.root, environ=selected['environ'], now=NOW), selected['inventory'])
            self.assertTrue(all(row['selection_assurance'] == 'declaration-only-unverified' for row in selected['inventory']['images']))
            with self.assertRaisesRegex(ValueError, 'nested'):
                public.project_catalog(json.loads(selected['image_artifacts'].read_text()), 'a' * 64)
            with self.assertRaises(SecurityDataError):
                expanded.selected_inventory(self.root, environ=selected['environ'], now=NOW + timedelta(days=4))
            with self.assertRaises(ValueError), patch.object(cli, 'source_binding', return_value=dict(source(), head_sha='f' * 40)):
                expanded.selected_inventory(self.root, environ=selected['environ'], now=NOW)
            selection = selected['image_selection']
            selection.write_text(selection.read_text().replace('TRUST_CI_RUNNER_IMAGE', 'ABSENT_RUNNER_IMAGE'))
            with self.assertRaises(SecurityDataError):
                expanded.selected_inventory(self.root, environ=selected['environ'], now=NOW)
        self.assertFalse(selection.exists())
        invalid = dict(catalog, inventory_sha256='f' * 64)
        path.write_bytes(encoded(invalid))
        with patch.object(public, 'project_catalog', side_effect=AssertionError('invalid original projected')):
            with self.assertRaises(ValueError):
                with cli.public_input_scope(self.root, *self.roots, context=context(), image_artifacts=path, now=NOW):
                    self.fail('invalid original accepted')

    def test_all_five_native_consumers_use_current_selection(self):
        self.require_api()
        sentinel = SecurityDataError('owned-current-selection-refusal')
        binding = dict(database='owned', source_id='artifact-license-catalog', source_url='owned',
                       content_sha256='a' * 64, payload_size=1, acquisition={}, coverage={})
        consumers = [lambda: expanded.security_obligations(self.root, environ={}, now=NOW),
                     lambda: expanded.known_vulnerability_report(self.root, environ={}, now=NOW),
                     lambda: expanded.known_vulnerability_check(self.root, environ={}, now=NOW),
                     lambda: expanded.run_checks(self.root, environ={}, now=NOW),
                     lambda: expanded.validate_data_source(binding, root=self.root, environ={}, now=NOW)]
        for consume in consumers:
            with patch.object(expanded, 'selected_inventory', side_effect=sentinel):
                with self.assertRaisesRegex(SecurityDataError, 'owned-current-selection-refusal'):
                    consume()

    def oci_fixture(self, *, config_platform='amd64', diff_id=None, extra_layer=False):
        _, oci = self.require_api()
        layout = self.snapshot / 'layout'
        blobs = layout / 'blobs/sha256'
        blobs.mkdir(parents=True)
        payload = io.BytesIO()
        with tarfile.open(fileobj=payload, mode='w') as archive:
            row = tarfile.TarInfo('owned.txt')
            row.size = 4
            archive.addfile(row, io.BytesIO(b'data'))
        layer = payload.getvalue()

        def blob(media, raw):
            identity = sha(raw)
            (blobs / identity).write_bytes(raw)
            return dict(mediaType=media, digest='sha256:' + identity, size=len(raw))

        layer_desc = blob(oci.TAR, layer)
        layers = [layer_desc] * (2 if extra_layer else 1)
        config = blob(oci.CONFIG, encoded(dict(os='linux', architecture=config_platform, rootfs=dict(
            type='layers', diff_ids=[diff_id or layer_desc['digest']] * len(layers)))))
        manifest = blob(oci.MANIFEST, encoded(dict(schemaVersion=2, mediaType=oci.MANIFEST, config=config, layers=layers)))
        (layout / 'oci-layout').write_bytes(encoded({'imageLayoutVersion': '1.0.0'}))
        (layout / 'index.json').write_bytes(encoded(dict(schemaVersion=2, manifests=[manifest])))
        reference = 'owned/fixture@' + manifest['digest']
        current = dict(complete=True, gaps=[], digest='c' * 64, images=[dict(reference=reference, platform='linux/amd64')])
        profile = dict(oci.LIMITS, images=[reference], platform='linux/amd64')
        catalog = dict(schema_version=1, inventory_sha256=current['digest'], records=[dict(reference=reference, platform='linux/amd64', layout=str(layout))])
        return oci, current, profile, catalog, blobs, config, layer_desc

    def test_oci_live_proof_and_scanner_input(self):
        oci, current, profile, catalog, _, config, _ = self.oci_fixture()
        with oci.import_layouts(catalog, current, profile, self.roots[2]) as images:
            image = images[0]
            retained = image.layout
            self.assertTrue(0 < image.remaining_seconds() <= 900)
            report = dict(SchemaVersion=2, ArtifactType='container_image', Metadata=dict(ImageID=config['digest']),
                          Results=[dict(Class='os-pkgs', Packages=[dict(Name='owned', Version='1')])])
            self.assertEqual(tools.image_report(report, image.reference, verified_oci=image)['package_count'], 1)
            with self.assertRaisesRegex(ValueError, 'config identity'):
                tools.image_report(dict(report, Metadata=dict(ImageID='sha256:' + 'f' * 64)), image.reference, verified_oci=image)
            (image.layout / 'index.json').write_bytes(b'{}')
            with self.assertRaisesRegex(ValueError, 'changed'):
                oci.scanner_identity(report, image)
        self.assertFalse(retained.exists())
        with self.assertRaisesRegex(ValueError, 'lifetime'):
            image.remaining_seconds()
        with self.assertRaises(ValueError):
            oci.scanner_identity(report, image)

        path = self.snapshot / 'scan-catalog.json'
        path.write_bytes(encoded(catalog))
        commands = []

        def process(command, cwd, scratch, **options):
            self.assertIn('--input', command)
            self.assertNotIn('--image-src', command)
            self.assertTrue(0 < options['timeout'] <= 900)
            self.assertTrue(Path(command[command.index('--input') + 1].split('@')[0]).is_relative_to(self.base))
            commands.append(command)
            Path(command[command.index('--output') + 1]).write_bytes(encoded(report))
            return SimpleNamespace(returncode=0)

        env = dict(GETZILLA_SECURITY_TOOLS=str(self.roots[2]), GETZILLA_SECURITY_IMAGE_ARTIFACTS=str(path),
                   GETZILLA_SECURITY_IMAGE_PROFILE=json.dumps(profile))
        with patch.object(tools, 'pinned_tool', return_value=self.base / 'never-executed-scanner'), patch.object(
                tools, 'trivy_database_source', return_value={'owned': 'mocked-db'}), patch.object(tools, '_process', side_effect=process):
            scanned = tools.scan_images(current, environ=env, now=NOW)
            self.assertEqual(scanned['outcome'], 'pass', scanned)
            self.assertEqual(len(commands), 1)
            path.write_bytes(encoded(dict(catalog, inventory_sha256='f' * 64)))
            self.assertEqual(tools.scan_images(current, environ=env, now=NOW)['outcome'], 'blocked')
            self.assertEqual(len(commands), 1)
        declared = copy.deepcopy(current)
        declared['images'][0]['selection_assurance'] = 'declaration-only-unverified'
        with patch.object(tools, 'pinned_tool', side_effect=AssertionError('declaration started a scanner')):
            self.assertEqual(tools.scan_images(declared, environ={}, now=NOW)['outcome'], 'blocked')

    def test_oci_graph_platform_layer_bounds_and_deadline_refuse(self):
        oci, current, profile, catalog, blobs, config, layer = self.oci_fixture()
        for key, value in (('max_storage_bytes', 1), ('max_compressed_bytes', 1), ('max_unpacked_bytes', 1),
                           ('max_manifest_bytes', 1), ('platform', 'linux/arm64')):
            with self.subTest(key=key), self.assertRaises(ValueError):
                with oci.import_layouts(catalog, current, dict(profile, **{key: value}), self.roots[2]):
                    self.fail('bound/platform ignored')
        with patch.object(oci.time, 'monotonic', side_effect=[0, 901]), self.assertRaisesRegex(ValueError, 'deadline'):
            with oci.import_layouts(catalog, current, profile, self.roots[2]):
                self.fail('deadline ignored')
        for desc in (config, layer):
            path = blobs / desc['digest'][7:]
            body = path.read_bytes()
            path.write_bytes(b'x' * len(body))
            with self.assertRaisesRegex(ValueError, 'digest'):
                with oci.import_layouts(catalog, current, profile, self.roots[2]):
                    self.fail('mutated graph imported')
            path.write_bytes(body)

    def test_default_inventory_and_cli_options_stay_optional(self):
        self.require_api()
        self.compose()
        self.assertEqual(expanded.selected_inventory(self.root, environ={}, now=NOW), inventory.collect_inventory(self.root))
        args = SimpleNamespace(refresh=False, provision_tools=False, input_profile=None)
        self.assertEqual(cli._evaluation_kwargs(args, None, None), dict(refresh=False, provision=False))
        args.image_artifacts = self.snapshot / 'catalog.json'
        args.image_selection = self.snapshot / 'selection.json'
        self.assertEqual(cli._evaluation_kwargs(args, None, None), dict(refresh=False, provision=False,
                         image_artifacts=args.image_artifacts, image_selection=args.image_selection))

    def test_empty_explicit_selections_cannot_become_default_inventory(self):
        self.require_api()
        self.compose()
        self.assertFalse(inventory.collect_inventory(self.root, image_bindings=[])['complete'])

    def test_ci_image_config_uses_the_same_current_selection_join(self):
        public, _ = self.require_api()
        path = self.root / '.getzilla/config/ci-images.json'
        path.parent.mkdir(parents=True)
        path.write_bytes(encoded(dict(schema_version=1, platform='linux/amd64', owned=dict(
            reference=SERVICE, image_id='sha256:' + 'c' * 64, source='https://example.invalid/owned'))))
        original = inventory.collect_inventory(self.root)
        self.assertTrue(original['complete'], original['gaps'])
        selected = public.selection_document(original, source(), public.validate_context(context(), source()), NOW.isoformat())
        current = inventory.declared_inventory(self.root, selected)
        self.assertTrue(current['complete'], current['gaps'])
        self.assertEqual(current['images'][0]['image_id'], original['images'][0]['image_id'])
        self.assertEqual(current['images'][0]['usage'], 'build-ci')
        self.assertIn('source_selection_sha256', current['images'][0])

    def test_guard_denies_foreign_io_and_unmocked_effects(self):
        with self.assertRaisesRegex(AssertionError, 'outside-fixture'):
            Path('/etc/hostname').read_bytes()
        with self.assertRaisesRegex(AssertionError, 'outside-fixture'):
            list(os.scandir(PROJECT))
        for effect in (lambda: subprocess.run(['never-execute']), lambda: socket.socket(),
                       lambda: ctypes.CDLL(None)):
            with self.assertRaisesRegex(AssertionError, 'effect denied'):
                effect()

    def test_explicit_runner_environment_refuses_ambient_and_duplicate_inputs(self):
        self.require_api()
        for body in ('      - TRUST_CI_RUNNER_IMAGE\n',
                     '      TRUST_CI_RUNNER_IMAGE:\n',
                     '      - TRUST_CI_RUNNER_IMAGE=' + RUNNER + '\n      - TRUST_CI_RUNNER_IMAGE=' + RUNNER + '\n'):
            (self.root / 'compose.yaml').write_text('services:\n  worker:\n    image: ' + SERVICE + '\n    environment:\n' + body)
            with patch.dict(os.environ, TRUST_CI_RUNNER_IMAGE=RUNNER):
                self.assertFalse(inventory.collect_inventory(self.root)['complete'])
        (self.root / 'compose.yaml').write_text('services:\n  worker:\n    image: ' + SERVICE + '\n    environment:\n      OTHER_IMAGE: mutable:latest\n')
        self.assertEqual(len(inventory.collect_inventory(self.root)['images']), 1)

    def test_original_catalog_drift_refuses_at_scope_exit(self):
        self.require_api()
        path, catalog = self.catalog()
        with self.assertRaisesRegex(SecurityDataError, 'original OCI catalog changed'):
            with cli.public_input_scope(self.root, *self.roots, context=context(), image_artifacts=path, now=NOW):
                path.write_bytes(encoded(dict(catalog, inventory_sha256='e' * 64)))

    def test_context_restores_after_nested_scope_and_exception(self):
        public, _ = self.require_api()
        with self.assertRaisesRegex(RuntimeError, 'owned-exception'):
            with public.bind_context(context(), source()):
                inner = dict(context(), run_attempt=2)
                with public.bind_context(inner, source()):
                    self.assertEqual(public.current_context()['run_attempt'], 2)
                self.assertEqual(public.current_context()['run_attempt'], 1)
                raise RuntimeError('owned-exception')
        self.assertIsNone(public.current_context())

    def test_supervisor_forwards_both_explicit_input_paths(self):
        self.require_api()
        args = SimpleNamespace(root=self.root, database=self.roots[0], artifacts=self.roots[1], tools=self.roots[2],
                               input_profile=self.snapshot / 'profile.json', json_out=self.snapshot / 'report.json',
                               refresh=False, provision_tools=False, family_records=None,
                               image_artifacts=self.snapshot / 'catalog.json', image_selection=self.snapshot / 'selection.json')
        profile = {'profile_sha256': 'c' * 64}
        expected = dict(kind='public-security-input-preparation', status='prepared', qualification='UNVERIFIED',
                        profile=profile, profile_sha256=profile['profile_sha256'])

        def execute(command, root, env, **options):
            self.assertEqual(command[command.index('--image-artifacts') + 1], str(args.image_artifacts))
            self.assertEqual(command[command.index('--image-selection') + 1], str(args.image_selection))
            self.assertEqual(root, self.root)
            self.assertEqual(options['timeout'], 600)
            args.json_out.write_bytes(encoded(expected))
            return SimpleNamespace(returncode=0, terminal_state='completed', cleanup_error=None)

        with patch.object(cli, 'execute', side_effect=execute):
            self.assertEqual(cli._supervised_preparation(args, profile), expected)

    def test_public_scope_refuses_outside_snapshot_and_missing_artifacts(self):
        self.require_api()
        with self.assertRaisesRegex(SecurityDataError, 'within the bound snapshot'):
            with cli.public_input_scope(self.root, *self.roots, context=context(), image_artifacts=self.base / 'outside.json', now=NOW):
                self.fail('outside catalog accepted')
        with self.assertRaisesRegex(SecurityDataError, 'complete snapshot'):
            with cli.public_input_scope(self.root, *reversed(self.roots), context=context(), now=NOW):
                self.fail('roots accepted in wrong roles')
        self.compose()
        with self.assertRaisesRegex(SecurityDataError, 'explicit complete local OCI artifacts'):
            with cli.public_input_scope(self.root, *self.roots, context=context(), now=NOW):
                self.fail('unqualified images accepted')

    def test_oci_config_platform_diff_id_and_aggregate_layers_are_checked(self):
        for kwargs, message in ((dict(config_platform='arm64'), 'platform'),
                                (dict(diff_id='sha256:' + 'f' * 64), 'uncompressed layer digest'),
                                (dict(extra_layer=True), 'resource bound')):
            with self.subTest(case=kwargs):
                # Each graph has its own fixture root; no bytes from prior
                # failed imports can substitute for this selected graph.
                with tempfile.TemporaryDirectory(dir=self.base) as directory:
                    snapshot = Path(directory)
                    previous = self.snapshot
                    self.snapshot = snapshot
                    try:
                        oci, current, profile, catalog, *_ = self.oci_fixture(**kwargs)
                        if kwargs.get('extra_layer'):
                            profile['max_layers'] = 1
                        with self.assertRaisesRegex(ValueError, message):
                            with oci.import_layouts(catalog, current, profile, self.roots[2]):
                                self.fail('invalid graph accepted')
                    finally:
                        self.snapshot = previous


class CoreApiReviewRegressionTests(unittest.TestCase):
    """Fresh review repairs; execute no earlier test method or scanner effect."""

    def setUp(self):
        scratch = PROJECT / '.getzilla/runtime/scratch'
        scratch.mkdir(parents=True, exist_ok=True)
        directory = tempfile.TemporaryDirectory(prefix='owned-oci-review-repair-', dir=scratch)
        self.addCleanup(directory.cleanup)
        self.base = Path(directory.name)
        self.workspace = self.base / 'workspace'
        self.workspace.mkdir()
        guard = fixture_guard(self.base)
        guard.__enter__()
        self.addCleanup(guard.__exit__, None, None, None)

    def nested_graph(self):
        layout = self.base / 'layout'
        blobs = layout / 'blobs/sha256'
        blobs.mkdir(parents=True)

        def store(media, raw):
            digest = hashlib.sha256(raw).hexdigest()
            (blobs / digest).write_bytes(raw)
            return dict(mediaType=media, digest='sha256:' + digest, size=len(raw))

        manifests, configs, layers = {}, {}, {}
        for architecture in ('amd64', 'arm64'):
            payload = io.BytesIO()
            body = ('owned-' + architecture).encode()
            with tarfile.open(fileobj=payload, mode='w') as archive:
                member = tarfile.TarInfo('platform.txt')
                member.size = len(body)
                archive.addfile(member, io.BytesIO(body))
            layers[architecture] = store(oci.TAR, payload.getvalue())
            configs[architecture] = store(oci.CONFIG, encoded(dict(os='linux', architecture=architecture,
                rootfs=dict(type='layers', diff_ids=[layers[architecture]['digest']]))))
            manifests[architecture] = store(oci.MANIFEST, encoded(dict(schemaVersion=2, mediaType=oci.MANIFEST,
                config=configs[architecture], layers=[layers[architecture]])))
            manifests[architecture]['platform'] = dict(os='linux', architecture=architecture)
        nested = store(oci.INDEX, encoded(dict(schemaVersion=2, mediaType=oci.INDEX,
            manifests=[manifests['amd64'], manifests['arm64']])))
        (layout / 'oci-layout').write_bytes(encoded({'imageLayoutVersion': '1.0.0'}))
        (layout / 'index.json').write_bytes(encoded(dict(schemaVersion=2, manifests=[nested])))
        reference = 'owned/review-graph@' + nested['digest']
        current = dict(complete=True, gaps=[], digest='d' * 64,
                       images=[dict(reference=reference, platform='linux/amd64')])
        profile = dict(oci.LIMITS, images=[reference], platform='linux/amd64',
                       max_images=1, max_compressed_bytes=65536, max_unpacked_bytes=65536,
                       max_storage_bytes=65536, max_manifest_bytes=16384, max_layers=2, deadline_seconds=30)
        catalog = dict(schema_version=1, inventory_sha256=current['digest'],
                       records=[dict(reference=reference, platform='linux/amd64', layout=str(layout))])
        return catalog, current, profile, blobs, manifests, configs, layers

    def test_nested_two_platform_graph_requires_nonselected_sibling(self):
        catalog, current, profile, blobs, manifests, configs, _ = self.nested_graph()
        with oci.import_layouts(catalog, current, profile, self.workspace) as images:
            self.assertEqual(len(images), 1)
            image = images[0]
            self.assertEqual(image.reference, current['images'][0]['reference'])
            self.assertEqual(image.platform, 'linux/amd64')
            self.assertEqual(image.manifest_digest, manifests['amd64']['digest'])
            self.assertEqual(image.config_digest, configs['amd64']['digest'])
            singleton = json.loads((image.layout / 'index.json').read_bytes())
            self.assertEqual(singleton['manifests'], [manifests['amd64']])
            oci.scanner_identity({'Metadata': {'ImageID': configs['amd64']['digest']}}, image)
            private = image.layout
        self.assertFalse(private.exists())

        sibling = blobs / manifests['arm64']['digest'][7:]
        original = sibling.read_bytes()
        for damage in ('missing', 'equal-size-corruption'):
            with self.subTest(damage=damage):
                if damage == 'missing':
                    sibling.unlink()
                else:
                    changed = bytearray(original)
                    changed[0] ^= 1
                    sibling.write_bytes(changed)
                    self.assertEqual(sibling.stat().st_size, len(original))
                try:
                    with self.assertRaises(oci.OCIError, msg='non-selected sibling must remain fully verified'):
                        with oci.import_layouts(catalog, current, profile, self.workspace):
                            pass
                finally:
                    sibling.write_bytes(original)

    def test_equal_size_retained_layer_damage_refuses_scanner_identity(self):
        catalog, current, profile, _, _, configs, layers = self.nested_graph()
        with oci.import_layouts(catalog, current, profile, self.workspace) as images:
            image = images[0]
            report = {'Metadata': {'ImageID': configs['amd64']['digest']}}
            oci.scanner_identity(report, image)
            layer = image.layout / 'blobs/sha256' / layers['amd64']['digest'][7:]
            original = layer.read_bytes()
            changed = bytearray(original)
            changed[512] ^= 1  # Alter file contents, retaining tar length/header.
            layer.write_bytes(changed)
            self.assertNotEqual(bytes(changed), original)
            self.assertEqual(layer.stat().st_size, len(original))
            self.assertEqual(report['Metadata']['ImageID'], image.config_digest)
            self.assertGreater(image.remaining_seconds(), 0)
            with self.assertRaisesRegex(oci.OCIError, 'Private OCI graph changed during scanning'):
                oci.scanner_identity(report, image)
            private = image.layout
        self.assertFalse(private.exists())


if __name__ == '__main__':
    unittest.main()
