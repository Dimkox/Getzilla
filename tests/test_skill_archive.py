"""Closed mandatory baseline resources retain custody in the existing lean archive."""
import hashlib
import io
from pathlib import Path
import stat
import json
import subprocess
import tempfile
import unittest
import zipfile
import warnings
from unittest import mock

from tests.test_install_on_demand import INSTALL, ROOT
from getzilla import baseline_assets as assets

BLOBS = '.getzilla/templates/baseline/blobs/'


def archive(items):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as output:
        for name, content, mode in items:
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = mode << 16
            with warnings.catch_warnings():
                warnings.simplefilter('ignore', UserWarning)
                output.writestr(info, content)
    return buffer.getvalue()


class ResourceArchiveTests(unittest.TestCase):
    def decode(self, raw):
        self.assertTrue(callable(getattr(assets, 'archive_entries', None)), 'closed archive reader is missing')
        return assets.archive_entries(raw)

    def test_closed_members_and_content_hashes(self):
        body = b'owned public text\n'
        digest = hashlib.sha256(body).hexdigest()
        result = self.decode(archive([('getzilla/example.py', b'VALUE=1\n', 0o644),
                                      ('templates/baseline/blobs/' + digest + '.txt', body, 0o644)]))
        self.assertEqual(result[BLOBS + digest + '.txt'], (body, 0o644))
        self.assertEqual(result['.getzilla/getzilla/example.py'][0], b'VALUE=1\n')

    def test_unknown_duplicate_links_modes_and_hashes_refuse(self):
        body = b'fixed\n'
        name = 'templates/baseline/blobs/' + hashlib.sha256(body).hexdigest() + '.txt'
        matrices = [ [('unknown/data', body, 0o644)], [(name, body, 0o644), (name, body, 0o644)],
                    [(name, body, stat.S_IFLNK | 0o777)], [(name, body, 0o755)],
                    [(name, b'changed', 0o644)], [('../' + name, body, 0o644)],
                    [('/' + name, body, 0o644)], [('getzilla/bad\\name.py', body, 0o644)] ]
        for items in matrices:
            with self.subTest(name=items[0][0], mode=items[0][2]):
                with self.assertRaises(ValueError):
                    self.decode(archive(items))

    def test_default_lean_contains_every_raw_blob_inside_container(self):
        payload = INSTALL.build_payload(ROOT, selection=INSTALL.PayloadSelection((), engine_archive=True))
        self.assertFalse(any(entry.path.startswith(BLOBS) for entry in payload))
        packed = next(entry for entry in payload if entry.path == INSTALL.ENGINE_ARCHIVE)
        members = self.decode(packed.content)
        source = {BLOBS+p.name: p.read_bytes() for p in (ROOT/BLOBS).glob('*.txt')}
        self.assertEqual(len(source), 522)
        self.assertEqual({p: body for p,(body,_mode) in members.items() if p.startswith(BLOBS)}, source)

    def test_lean_load_and_installed_source_roundtrip_are_complete(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)/'consumer'
            selection = INSTALL.PayloadSelection((), engine_archive=True)
            INSTALL._materialize_new(ROOT, target, include_dependencies=False, include_optional=False, selection=selection)
            for component in ('bmad','spec-kit','superpowers'):
                self.assertEqual(assets.load(component,'codex',source_root=target), assets.load(component,'codex',source_root=ROOT))
            self.assertEqual(INSTALL.build_payload(target,selection=selection), INSTALL.build_payload(ROOT,selection=selection))
            self.assertLess(len(INSTALL.build_payload(target,selection=selection)),400)
            # An installed manifest does not excuse loss of a declared Core file.
            (target/'scripts/getzilla_route.py').unlink()
            with self.assertRaises(INSTALL.UnsafeInstallTarget):
                INSTALL.build_payload(target, selection=selection)

    def test_installed_manifest_cannot_omit_mandatory_component_files(self):
        from getzilla.component_state import MANIFEST, decode_manifest, encode_manifest
        cases = (('core','scripts/getzilla_route.py',False),
                 ('core','engineering/vendor-custody/bmad-whitespace.md',False),
                 ('factory','factory/pyproject.toml',True))
        for component, missing, factory in cases:
            with self.subTest(component=component, missing=missing), tempfile.TemporaryDirectory() as directory:
                target = Path(directory)/'consumer'
                selection = INSTALL.PayloadSelection((),factory=factory,engine_archive=True)
                INSTALL._materialize_new(ROOT,target,include_dependencies=False,include_optional=False,selection=selection)
                manifest = decode_manifest((target/MANIFEST).read_bytes())
                manifest['components'][component]['files'].remove(missing)
                manifest['components'][component]['owned'].pop(missing)
                (target/MANIFEST).write_bytes(encode_manifest(manifest))
                (target/missing).unlink()
                with self.assertRaises(INSTALL.UnsafeInstallTarget):
                    INSTALL.build_payload(target,selection=selection)

    def test_conflicting_loose_archive_resource_refuses(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)/'consumer'
            INSTALL._materialize_new(ROOT, root, include_dependencies=False, include_optional=False,
                                     selection=INSTALL.PayloadSelection((), engine_archive=True))
            config = json.loads((ROOT/'.getzilla/config/toolchain.json').read_bytes())
            component = next(item for item in config['workflow_sources']['components'] if item['id']=='bmad')
            metadata = json.loads((ROOT/component['generated_assets']['codex-sh']['path']).read_bytes())
            raw = ROOT/BLOBS/(metadata['files'][0]['sha256']+'.txt')
            loose = root/BLOBS/raw.name
            loose.parent.mkdir(parents=True)
            loose.write_bytes(b'conflicting loose bytes')
            with self.assertRaises(ValueError):
                assets.load('bmad', 'codex', source_root=root)
            with self.assertRaises(INSTALL.UnsafeInstallTarget):
                INSTALL.build_payload(root, selection=INSTALL.PayloadSelection((), engine_archive=True))

    def test_missing_entire_resource_set_cannot_be_repacked_as_complete(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)/'consumer'
            selection = INSTALL.PayloadSelection((), engine_archive=True)
            INSTALL._materialize_new(ROOT, root, include_dependencies=False, include_optional=False, selection=selection)
            members = self.decode((root/INSTALL.ENGINE_ARCHIVE).read_bytes())
            (root/INSTALL.ENGINE_ARCHIVE).write_bytes(archive([
                (p.removeprefix('.getzilla/'), body, mode)
                for p,(body,mode) in members.items() if not p.startswith(BLOBS)]))
            with self.assertRaises(INSTALL.UnsafeInstallTarget):
                INSTALL.build_payload(root, selection=selection)

    def test_archived_vendor_claim_requires_each_actual_git_layer(self):
        from getzilla.verification_dispositions import Dispositions
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)/'consumer'
            INSTALL._materialize_new(ROOT, root, include_dependencies=False, include_optional=False,
                                     selection=INSTALL.PayloadSelection((), engine_archive=True))
            def git(*args):
                return subprocess.run(['git', '-C', str(root), '-c', 'user.name=Fixture',
                                       '-c', 'user.email=fixture@example.invalid', *args],
                                      check=True, capture_output=True)
            git('init', '-q')
            git('add', '.')
            git('commit', '-qm', 'owned fixture')
            policy = Dispositions(root)
            entry = policy.entries[0]
            self.assertTrue(entry['path'].startswith(BLOBS))
            for layer in ('worktree', 'index', 'HEAD'):
                self.assertIsNotNone(policy.whitespace(entry['path'], entry['line'],
                                                      policy.snapshots(layer), entry['rule']))
            original = (root/INSTALL.ENGINE_ARCHIVE).read_bytes()
            members = self.decode(original)
            # The same logical resource cannot borrow a worktree container to cover
            # a different staged/committed physical container.
            changed = archive([(p.removeprefix('.getzilla/'), body, mode)
                               for p, (body, mode) in members.items() if p != entry['path']])
            (root/INSTALL.ENGINE_ARCHIVE).write_bytes(changed)
            git('add', INSTALL.ENGINE_ARCHIVE)
            (root/INSTALL.ENGINE_ARCHIVE).write_bytes(original)
            self.assertIsNone(policy.whitespace(entry['path'], entry['line'],
                                                policy.snapshots('index'), entry['rule']))
            self.assertIsNotNone(policy.whitespace(entry['path'], entry['line'],
                                                   policy.snapshots('HEAD'), entry['rule']))
            git('commit', '-qm', 'different actual container')
            self.assertIsNone(policy.whitespace(entry['path'], entry['line'],
                                                policy.snapshots('HEAD'), entry['rule']))
            git('add', INSTALL.ENGINE_ARCHIVE)
            policy.assert_current()

    def test_ordinary_disposition_source_keeps_two_million_byte_cap(self):
        from getzilla.verification_dispositions import Dispositions, DispositionError
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(['git', 'init', '-q', str(root)], check=True)
            (root/'ordinary.txt').write_bytes(b'x'*2_000_001)
            subprocess.run(['git', '-C', str(root), 'add', 'ordinary.txt'], check=True)
            with self.assertRaises(DispositionError):
                Dispositions(root)._read('ordinary.txt')


class ArchiveUpgradeTests(unittest.TestCase):
    from tests.test_getzilla_upgrade import ProjectSyncTests as _Fixture
    setUp = _Fixture.setUp
    commit = _Fixture.commit
    select = _Fixture.select

    def legacy_resource(self):
        from getzilla.component_state import MANIFEST, encode_manifest, record_owned
        manifest = self.select(())
        raw = next((ROOT/BLOBS).glob('*.txt'))
        path = BLOBS+raw.name
        destination = self.project/path
        destination.parent.mkdir(parents=True)
        destination.write_bytes(raw.read_bytes())
        record_owned(manifest, path, raw.read_bytes(), 0o644)
        (self.project/MANIFEST).write_bytes(encode_manifest(manifest))
        return path

    def test_only_actual_owned_legacy_members_retire_and_repeat_is_noop(self):
        from tests.test_getzilla_upgrade import upgrade, git
        path = self.legacy_resource()
        foreign = self.project/BLOBS/'foreign.py'
        foreign.parent.mkdir(parents=True, exist_ok=True)
        # This name is not an incoming archive member, even though it is Python.
        foreign.write_bytes(b'# custom inert file\n')
        self.commit('owned legacy resource and unrelated file')
        upgrade.sync_project(ROOT, self.project)
        self.assertFalse((self.project/path).exists())
        self.assertEqual(foreign.read_bytes(), b'# custom inert file\n')
        self.assertTrue((self.project/INSTALL.ENGINE_ARCHIVE).is_file())
        before = git(self.project, 'rev-parse', 'HEAD')
        upgrade.sync_project(ROOT, self.project)
        self.assertEqual(git(self.project, 'rev-parse', 'HEAD'), before)

    def test_identical_unowned_legacy_member_cannot_retire(self):
        from tests.test_getzilla_upgrade import upgrade, git
        from getzilla.component_state import MANIFEST, encode_manifest, read_state
        path = self.legacy_resource()
        manifest = read_state(self.project).manifest
        manifest['components']['core']['owned'].pop(path)
        (self.project/MANIFEST).write_bytes(encode_manifest(manifest))
        self.commit('identical but unowned resource')
        before = git(self.project, 'rev-parse', 'HEAD')
        with self.assertRaises(upgrade.UpdateError):
            upgrade.sync_project(ROOT, self.project)
        self.assertTrue((self.project/path).is_file())
        self.assertEqual(git(self.project, 'rev-parse', 'HEAD'), before)

    def test_changed_resource_and_consumer_policy_refuse_before_writes(self):
        from tests.test_getzilla_upgrade import upgrade, git
        path = self.legacy_resource()
        self.commit('owned legacy resource')
        original = (self.project/path).read_bytes()
        (self.project/path).write_bytes(b'local changed bytes')
        self.commit('local changed resource')
        before = git(self.project, 'rev-parse', 'HEAD')
        with self.assertRaises((upgrade.UpdateError, INSTALL.UnsafeInstallTarget)):
            upgrade.sync_project(ROOT, self.project)
        self.assertEqual(git(self.project, 'rev-parse', 'HEAD'), before)
        self.assertEqual((self.project/path).read_bytes(), b'local changed bytes')
        (self.project/path).write_bytes(original)
        policy = self.project/'engineering/verification-dispositions.json'
        policy.parent.mkdir(parents=True)
        policy.write_bytes(b'{"schema_version":1,"dispositions":[]}\n')
        self.commit('consumer policy')
        before = git(self.project, 'rev-parse', 'HEAD')
        with self.assertRaises(upgrade.UpdateError):
            upgrade.sync_project(ROOT, self.project)
        self.assertEqual(git(self.project, 'rev-parse', 'HEAD'), before)
        self.assertEqual(policy.read_bytes(), b'{"schema_version":1,"dispositions":[]}\n')


class ResourceModeContractTests(unittest.TestCase):
    """Linux pure-data controls of the existing host-mode projection, not native Windows."""
    def resource_inputs(self):
        config_path = '.getzilla/config/toolchain.json'
        metadata = {config_path:(ROOT/config_path).read_bytes()}
        config = json.loads(metadata[config_path])
        entries = {}
        for component in config['workflow_sources']['components']:
            for record in component['generated_assets'].values():
                raw = (ROOT/record['path']).read_bytes()
                metadata[record['path']] = raw
                for item in json.loads(raw)['files']:
                    path = BLOBS+item['sha256']+'.txt'
                    if path not in entries:
                        entries[path] = ((ROOT/path).read_bytes(),0o644)
        self.assertEqual(len(entries),522)
        return entries,metadata.__getitem__

    def test_resource_modes_preserve_posix_strictness(self):
        from getzilla import fsx
        entries,read = self.resource_inputs()
        with mock.patch.object(fsx,'WINDOWS',False):
            assets.validate_resources(entries,read)
            for mode in (0o664,0o666,0o755):
                projected = {path:(body,mode) for path,(body,_mode) in entries.items()}
                with self.subTest(mode=mode),self.assertRaises(ValueError):
                    assets.validate_resources(projected,read)

    def test_windows_projection_uses_mode_contract_without_skipping_custody(self):
        from getzilla import fsx
        entries,read = self.resource_inputs()
        projected = {path:(body,0o666) for path,(body,_mode) in entries.items()}
        first = next(iter(projected))
        body = projected[first][0]
        self.assertTrue(body)
        with mock.patch.object(fsx,'WINDOWS',True):
            assets.validate_resources(projected,read)
            readonly = {path:(data,0o444) for path,(data,_mode) in projected.items()}
            with self.assertRaises(ValueError):
                assets.validate_resources(readonly,read)
            for kind in ('missing','extra','hash','size'):
                changed = dict(projected)
                if kind == 'missing':
                    changed.pop(first)
                elif kind == 'extra':
                    extra = BLOBS+'0'*64+'.txt'
                    self.assertNotIn(extra,changed)
                    changed[extra] = (b'not declared',0o666)
                elif kind == 'hash':
                    changed[first] = (bytes([body[0]^1])+body[1:],0o666)
                else:
                    changed[first] = (body+b'\n',0o666)
                with self.subTest(kind=kind),self.assertRaises(ValueError):
                    assets.validate_resources(changed,read)

    def test_zip_metadata_modes_remain_literal_under_both_host_projections(self):
        from getzilla import fsx
        body = b'fixed public archive text\n'
        name = 'templates/baseline/blobs/'+hashlib.sha256(body).hexdigest()+'.txt'
        for windows in (False,True):
            with self.subTest(windows=windows),mock.patch.object(fsx,'WINDOWS',windows):
                self.assertEqual(assets.archive_entries(archive([(name,body,0o644)])),
                                 {'.getzilla/'+name:(body,0o644)})
                for mode in (0o666,0o755,stat.S_IFLNK|0o777):
                    with self.subTest(mode=mode),self.assertRaises(ValueError):
                        assets.archive_entries(archive([(name,body,mode)]))
