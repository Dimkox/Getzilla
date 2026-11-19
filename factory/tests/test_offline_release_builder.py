"""Deterministic, network-free Factory release builder contracts."""

import hashlib
import io
from contextlib import contextmanager
import importlib.util
import json
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import tarfile
import unittest
from unittest.mock import patch
import warnings
import zipfile


RUNTIME = Path(__file__).resolve().parents[1] / "runtime"


def load(name):
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, RUNTIME / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


setup = load("setup_manager")


class OfflineReleaseBuilderTests(unittest.TestCase):
    @contextmanager
    def admitted_target(self, version='3.12.3', *, releaselevel='final'):
        environment = {'sys_platform': 'linux', 'os_name': 'posix', 'platform_system': 'Linux',
                       'platform_machine': 'x86_64', 'implementation_name': 'cpython',
                       'platform_python_implementation': 'CPython', 'python_version': '3.12',
                       'python_full_version': version}
        original_run, original_read = subprocess.run, Path.read_text
        def run(command, *args, **kwargs):
            if command[0] == '/usr/bin/python3.12':
                text = ('Python ' + version + '\n' if command[-1] == '--version' else
                        json.dumps({'environment': environment, 'pointer_bits': 64, 'releaselevel': releaselevel}))
                return subprocess.CompletedProcess(command, 0, text, '')
            return original_run(command, *args, **kwargs)
        def read(path, *args, **kwargs):
            if path == Path('/etc/os-release'):
                return 'ID=ubuntu\nVERSION_ID="24.04"\n'
            return original_read(path, *args, **kwargs)
        with patch.object(self.builder.subprocess, 'run', side_effect=run), \
             patch.object(Path, 'read_text', read), \
             patch.object(self.builder.platform, 'system', return_value='Linux'), \
             patch.object(self.builder.platform, 'machine', return_value='x86_64'):
            yield environment

    def patch_lock(self, marker, *, requirement='>=3.12,<3.13', include_wheel=True):
        wheel = self.wheelhouse / 'patch_required-1.0.0-py3-none-any.whl'
        with zipfile.ZipFile(wheel, 'w') as archive:
            archive.writestr('patch_required/__init__.py', b'VALUE=2\n')
        lock = self.repo / 'factory/uv.lock'
        text = lock.read_text().replace('>=3.12,<3.13', requirement)
        text = text.replace('dependencies = [{name = "demo"}]',
                            'dependencies = [{name = "demo"}, {name = "patch-required", marker = "' + marker + '"}]')
        text += ('\n[[package]]\nname = "patch-required"\nversion = "1.0.0"\n'
                 'wheels = [{url = "https://invalid.example/' + wheel.name + '", hash = "sha256:'
                 + hashlib.sha256(wheel.read_bytes()).hexdigest() + '"}]\n')
        lock.write_text(text)
        subprocess.run(['git', 'add', '.'], cwd=self.repo, check=True)
        subprocess.run(['git', 'commit', '-qm', 'patch-sensitive runtime dependency'], cwd=self.repo, check=True)
        self.head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=self.repo, text=True).strip()
        if not include_wheel:
            wheel.unlink()
        return lock

    def setUp(self):
        self.builder = load("build_offline_release")
        # Explicit portable diagnostic target; this does not attest the host.
        self.environment = {'sys_platform': 'linux', 'os_name': 'posix', 'platform_system': 'Linux',
                            'platform_machine': 'x86_64', 'implementation_name': 'cpython',
                            'platform_python_implementation': 'CPython', 'python_version': '3.12',
                            'python_full_version': '3.12.3'}
        self.temp = tempfile.TemporaryDirectory(prefix="factory-release-builder-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.repo = self.base / "repo"
        package = self.repo / "factory/src/getzilla_factory"
        package.mkdir(parents=True)
        (package / "__init__.py").write_text("__version__='1.2.3'\n")
        (package / "server.py").write_text("raise SystemExit(0)\n")
        (self.repo / "LICENSE").write_bytes((RUNTIME.parents[1] / "LICENSE").read_bytes())
        subprocess.run(["git", "init", "-q", "-b", "main"], cwd=self.repo, check=True)
        subprocess.run(["git", "config", "user.name", "test"], cwd=self.repo, check=True)
        subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=self.repo, check=True)
        self.wheelhouse = self.base / "wheelhouse"
        self.wheelhouse.mkdir()
        wheel = self.wheelhouse / "demo-1.0.0-py3-none-any.whl"
        with zipfile.ZipFile(wheel, "w") as archive:
            info = zipfile.ZipInfo("demo/__init__.py", (2020, 1, 1, 0, 0, 0))
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(info, b"VALUE=1\n")
        lock = self.repo / "factory/uv.lock"
        lock.write_text(
            'version = 1\nrevision = 3\nrequires-python = ">=3.12,<3.13"\n\n'
            '[[package]]\nname = "getzilla-factory"\nversion = "1.2.3"\ndependencies = [{name = "demo"}]\n\n'
            '[[package]]\nname = "demo"\nversion = "1.0.0"\n'
            f'wheels = [{{ url = "https://invalid.example/{wheel.name}", '
            f'hash = "sha256:{hashlib.sha256(wheel.read_bytes()).hexdigest()}", size = {wheel.stat().st_size} }}]\n'
        )
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-qm", "fixture"], cwd=self.repo, check=True)
        self.head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=self.repo, text=True).strip()
        self.inventory = self.base / "inventory.json"
        self.inventory.write_text(json.dumps({
            "schema_version": "factory-runtime-wheels/v1",
            "profile": "ubuntu-24.04-x86_64-cpython312",
            "lock_sha256": hashlib.sha256(lock.read_bytes()).hexdigest(),
            "wheels": [{"name": "demo", "version": "1.0.0", "filename": wheel.name,
                        "sha256": hashlib.sha256(wheel.read_bytes()).hexdigest()}],
        }))

    def build(self, stem):
        return self.builder.build_release(
            repository=self.repo, expected_head=self.head, wheelhouse=self.wheelhouse,
            inventory=self.inventory, output=self.base / stem, product_version="1.2.3",
            enforce_host=False, target_environment=self.environment,
        )

    def assert_no_release(self, stem):
        for suffix in ('.zip', '.manifest.json', '.sha256'):
            self.assertFalse(Path(str(self.base / stem) + suffix).exists())

    def test_project_license_retained_in_archive_and_manifest(self):
        expected = (self.repo / 'LICENSE').read_bytes()
        self.assertIn(b'Copyright (c) 2026 Dimkox', expected)
        result = self.build('project-license')
        with zipfile.ZipFile(result['archive']) as archive:
            self.assertEqual(archive.read('legal/project/LICENSE'), expected)
        manifest = json.loads(Path(result['manifest']).read_bytes())
        entry = next(item for item in manifest['files'] if item['path'] == 'legal/project/LICENSE')
        self.assertEqual(entry, {'path': 'legal/project/LICENSE', 'size': len(expected),
                                'sha256': hashlib.sha256(expected).hexdigest(), 'mode': 0o644})

    def test_project_license_missing_refuses_without_output(self):
        (self.repo / 'LICENSE').unlink()
        self.commit_fixture('missing project license')
        with self.assertRaisesRegex(setup.InstallerError, 'PROJECT_LICENSE_MISMATCH'):
            self.build('missing-license')
        self.assert_no_release('missing-license')

    def test_project_license_symlink_refuses_without_output(self):
        license_path = self.repo / 'LICENSE'
        external = self.base / 'external-license'
        external.write_bytes(license_path.read_bytes())
        license_path.unlink()
        license_path.symlink_to(external)
        self.commit_fixture('linked project license')
        with self.assertRaisesRegex(setup.InstallerError, 'PROJECT_LICENSE_MISMATCH'):
            self.build('linked-license')
        self.assert_no_release('linked-license')

    def test_project_license_changed_after_clean_check_refuses_without_output(self):
        original = self.builder._git
        def git(repository, *arguments):
            result = original(repository, *arguments)
            if arguments == ('ls-tree', self.head, '--', 'LICENSE'):
                (self.repo / 'LICENSE').write_bytes(b'replaced after clean source check\n')
            return result
        with patch.object(self.builder, '_git', side_effect=git):
            with self.assertRaisesRegex(setup.InstallerError, 'PROJECT_LICENSE_MISMATCH'):
                self.build('changed-license')
        self.assert_no_release('changed-license')

    def test_project_license_copies_changed_committed_terms_verbatim(self):
        expected = b'Future source license fixture: retain actual bytes, including \xff.\n'
        (self.repo / 'LICENSE').write_bytes(expected)
        self.commit_fixture('different committed license')
        result = self.build('future-license')
        with zipfile.ZipFile(result['archive']) as archive:
            self.assertEqual(archive.read('legal/project/LICENSE'), expected)

    @contextmanager
    def selected_legal_fixture(self):
        # Tiny synthetic wheel exercises the real archive/manifest publication seam.
        # It is not a qualification of the publisher wheel or target interpreter.
        relative = Path('.getzilla/config/license-exception-inputs/factory-source-delivery-v1')
        source = RUNTIME.parents[1] / relative
        for original in source.rglob('*'):
            if not original.is_file():
                continue
            destination = self.repo / relative / original.relative_to(source)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(original.read_bytes())
            destination.chmod(stat.S_IMODE(original.stat().st_mode))
        filename = 'certifi-2026.10.19-py3-none-any.whl'
        wheel = self.wheelhouse / filename
        with zipfile.ZipFile(wheel, 'w') as archive:
            archive.writestr('certifi/cacert.pem', b'fixture certificate data\n')
            archive.writestr('certifi-2026.10.19.dist-info/licenses/LICENSE', b'original fixture notice\n')
        digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
        lock = self.repo / 'factory/uv.lock'
        text = lock.read_text().replace('dependencies = [{name = "demo"}]',
                    'dependencies = [{name = "demo"}, {name = "certifi"}]')
        text += ('\n[[package]]\nname = "certifi"\nversion = "2026.10.19"\n'
                 'wheels = [{url = "https://invalid.example/' + filename + '", hash = "sha256:' + digest + '"}]\n')
        lock.write_text(text)
        self.inventory.write_text(json.dumps(self.builder.derive_inventory(lock, target_environment=self.environment)))
        source_map_path = self.repo / relative / 'certifi-2026.10.19-source-map.json'
        source_map = json.loads(source_map_path.read_text())
        source_map['wheel']['sha256'] = digest
        source_map_path.write_text(json.dumps(source_map, sort_keys=True, indent=2) + '\n')
        provenance = {'certifi': (source_map_path.name, hashlib.sha256(source_map_path.read_bytes()).hexdigest())}
        self.commit_fixture('selected legal fixture')
        subject = {'certifi': ('2026.10.19', filename, digest)}
        with patch.object(self.builder, '_LEGAL_SUBJECTS', subject, create=True), \
             patch.object(self.builder, '_LEGAL_PROVENANCE', provenance):
            yield self.repo / relative

    def commit_fixture(self, message):
        subprocess.run(['git', 'add', '-f', '.'], cwd=self.repo, check=True)
        subprocess.run(['git', 'commit', '-qm', message], cwd=self.repo, check=True)
        self.head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=self.repo, text=True).strip()

    def test_selected_legal_payload_is_retained_in_real_archive_and_manifest(self):
        with self.selected_legal_fixture() as inputs:
            result = self.build('legal')
            verified = setup.verify_release(archive=Path(result['archive']), manifest=Path(result['manifest']),
                archive_sha256=result['archive_sha256'], manifest_sha256=result['manifest_sha256'])
            contents = {name: body for name, body, _ in verified.files}
            self.assertIn('legal/sources/certifi-2026.10.19.tar.gz', contents)
            snapshot = json.loads((inputs / 'certifi-2026.10.19-snapshot.json').read_text())
            with tarfile.open(fileobj=io.BytesIO(contents['legal/sources/certifi-2026.10.19.tar.gz'])) as archive:
                files = {member.name: member for member in archive}
                self.assertEqual({member['original_path'] for member in snapshot['members']}, set(files))
                for member in snapshot['members']:
                    observed = files[member['original_path']]
                    body = archive.extractfile(observed).read()
                    self.assertEqual((inputs / 'vendor/certifi-2026.10.19' / member['path']).read_bytes(), body)
                    self.assertEqual(member['mode'], observed.mode)
                    self.assertEqual((0, 0, 0, '', ''),
                                     (observed.mtime, observed.uid, observed.gid, observed.uname, observed.gname))
            self.assertEqual((inputs / 'MPL-2.0.txt').read_bytes(), contents['legal/licenses/MPL-2.0.txt'])
            self.assertEqual(b'original fixture notice\n',
                             contents['site-packages/certifi-2026.10.19.dist-info/licenses/LICENSE'])
            source_map = json.loads(contents['legal/source-map.json'])
            self.assertEqual(['certifi'], [x['package'] for x in source_map['packages']])
            self.assertFalse(any('psycopg' in name or 'GPL-3.0' in name for name in contents))
            repeated = self.build('legal-repeat')
            self.assertEqual(result['archive_sha256'], repeated['archive_sha256'])
            with self.assertRaises(setup.InstallerError) as error:
                self.build('legal')
            self.assertEqual('OUTPUT_EXISTS', error.exception.code)

    def test_changed_legal_source_or_unknown_subject_refuses_before_publication(self):
        with self.selected_legal_fixture() as inputs:
            archive = inputs / 'vendor/certifi-2026.10.19/certifi/core.py'
            archive.write_bytes(archive.read_bytes() + b'changed')
            self.commit_fixture('tampered source fixture')
            with self.assertRaises(setup.InstallerError) as error:
                self.build('tampered-legal')
            self.assertEqual('LEGAL_INPUT_MISMATCH', error.exception.code)
            self.assertFalse(any(self.base.glob('tampered-legal*')))
            subject = dict(self.builder._LEGAL_SUBJECTS)
            subject['certifi'] = ('different', *subject['certifi'][1:])
            with patch.object(self.builder, '_LEGAL_SUBJECTS', subject):
                with self.assertRaises(setup.InstallerError) as error:
                    self.build('wrong-subject')
            self.assertEqual('LEGAL_DEPENDENCY_MISMATCH', error.exception.code)
            self.assertFalse(any(self.base.glob('wrong-subject*')))

    def test_symlinked_legal_input_refuses_before_publication(self):
        with self.selected_legal_fixture() as inputs:
            source = inputs / 'MPL-2.0.txt'
            target = self.base / 'external-license'
            target.write_bytes(source.read_bytes())
            source.unlink()
            source.symlink_to(target)
            self.commit_fixture('linked legal fixture')
            with self.assertRaises(setup.InstallerError) as error:
                self.build('linked-legal')
            self.assertEqual('LEGAL_INPUT_MISMATCH', error.exception.code)
            self.assertFalse(any(self.base.glob('linked-legal*')))

    def test_source_delivery_distinguishes_repacked_container_from_original(self):
        with self.selected_legal_fixture():
            result = self.build('source-repack')
            with zipfile.ZipFile(result['archive']) as archive:
                source_map = json.loads(archive.read('legal/source-map.json'))
                package = source_map['packages'][0]
                self.assertIn('source_delivery', package)
                delivered = archive.read('legal/sources/certifi-2026.10.19.tar.gz')
                self.assertEqual(hashlib.sha256(delivered).hexdigest(), package['source_delivery']['sha256'])
                self.assertNotEqual(package['source']['original_archive_sha256'], package['source_delivery']['sha256'])
                self.assertEqual('canonical-repack-of-unchanged-source', package['source_delivery']['representation'])

    def test_unlisted_snapshot_member_refuses_before_publication(self):
        with self.selected_legal_fixture() as inputs:
            extra = inputs / 'vendor/certifi-2026.10.19/unlisted.py'
            extra.parent.mkdir(parents=True, exist_ok=True)
            extra.write_text('UNLISTED = True\n')
            self.commit_fixture('unexpected snapshot member')
            with self.assertRaises(setup.InstallerError) as error:
                self.build('extra-snapshot')
            self.assertEqual('LEGAL_INPUT_MISMATCH', error.exception.code)
            self.assertFalse(any(self.base.glob('extra-snapshot*')))

    def test_snapshot_original_mode_and_missing_member_are_required(self):
        with self.selected_legal_fixture() as inputs:
            manifest = json.loads((inputs / 'certifi-2026.10.19-snapshot.json').read_text())
            executable = next(member for member in manifest['members'] if member['mode'] == 0o755)
            source = inputs / 'vendor/certifi-2026.10.19' / executable['path']
            source.chmod(0o644)
            self.commit_fixture('source executable mode changed')
            with self.assertRaises(setup.InstallerError) as error:
                self.build('mode-snapshot')
            self.assertEqual('LEGAL_INPUT_MISMATCH', error.exception.code)
            self.assertFalse(any(self.base.glob('mode-snapshot*')))
            source.unlink()
            self.commit_fixture('required source member missing')
            with self.assertRaises(setup.InstallerError) as error:
                self.build('missing-snapshot')
            self.assertEqual('LEGAL_INPUT_MISMATCH', error.exception.code)
            self.assertFalse(any(self.base.glob('missing-snapshot*')))

    def test_snapshot_extra_empty_directory_and_source_symlink_refuse(self):
        with self.selected_legal_fixture() as inputs:
            extra = inputs / 'vendor/certifi-2026.10.19/extra-empty-directory'
            extra.mkdir()
            with self.assertRaises(setup.InstallerError) as error:
                self.build('directory-snapshot')
            self.assertEqual('LEGAL_INPUT_MISMATCH', error.exception.code)
            self.assertFalse(any(self.base.glob('directory-snapshot*')))
            extra.rmdir()
            source = inputs / 'vendor/certifi-2026.10.19/certifi/core.py'
            target = self.base / 'linked-source-body'
            target.write_bytes(source.read_bytes())
            source.unlink()
            source.symlink_to(target)
            self.commit_fixture('linked snapshot source member')
            with self.assertRaises(setup.InstallerError) as error:
                self.build('symlink-snapshot')
            self.assertEqual('LEGAL_INPUT_MISMATCH', error.exception.code)
            self.assertFalse(any(self.base.glob('symlink-snapshot*')))

    def test_literal_upstream_cfg_whitespace_keeps_text_diffs_and_other_checks(self):
        with self.selected_legal_fixture() as inputs:
            result = subprocess.run(['git', 'diff', '--check', 'HEAD~', 'HEAD'], cwd=self.repo,
                                    capture_output=True, text=True, check=False)
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            prefix = '.getzilla/config/license-exception-inputs/factory-source-delivery-v1/'
            for package in ('certifi-2026.10.19', 'psycopg-3.3.4'):
                relative = prefix + 'vendor/' + package + '/setup.cfg'
                manifest = json.loads((inputs / (package + '-snapshot.json')).read_text())
                member = next(row for row in manifest['members'] if row['path'] == 'setup.cfg')
                self.assertEqual(member['sha256'], hashlib.sha256((self.repo / relative).read_bytes()).hexdigest())
                changed = subprocess.check_output(['git', 'diff', '--numstat', 'HEAD~', 'HEAD', '--', relative],
                                                  cwd=self.repo, text=True)
                self.assertRegex(changed, r'^\d+\t\d+\t')
                attributes = subprocess.check_output(['git', 'check-attr', 'diff', '--', relative],
                                                     cwd=self.repo, text=True)
                self.assertIn(': diff: unspecified', attributes)
            source = self.repo / 'factory/src/getzilla_factory/server.py'
            source.write_text(source.read_text() + '# product whitespace remains checked  \n')
            result = subprocess.run(['git', 'diff', '--check'], cwd=self.repo,
                                    capture_output=True, text=True, check=False)
            self.assertNotEqual(0, result.returncode)
            self.assertIn('trailing whitespace', result.stdout)

    def test_missing_legal_text_refuses_before_publication(self):
        with self.selected_legal_fixture() as inputs:
            (inputs / 'MPL-2.0.txt').unlink()
            self.commit_fixture('missing required text')
            with self.assertRaises(setup.InstallerError) as error:
                self.build('missing-legal')
            self.assertEqual('LEGAL_INPUT_MISMATCH', error.exception.code)
            self.assertFalse(any(self.base.glob('missing-legal*')))

    def test_linked_legal_parent_and_duplicate_destination_refuse(self):
        with self.selected_legal_fixture() as inputs:
            files = self.builder._LEGAL_FILES['certifi']
            with patch.object(self.builder, '_LEGAL_FILES', {'certifi': (files[0], files[0])}):
                with self.assertRaises(setup.InstallerError) as error:
                    self.build('collision-legal')
            self.assertEqual('LEGAL_FILE_COLLISION', error.exception.code)
            self.assertFalse(any(self.base.glob('collision-legal*')))
            moved = inputs.with_name('retained-inputs')
            inputs.rename(moved)
            inputs.symlink_to(moved.name, target_is_directory=True)
            self.commit_fixture('linked legal parent')
            with self.assertRaises(setup.InstallerError) as error:
                self.build('parent-legal')
            self.assertEqual('LEGAL_INPUT_MISMATCH', error.exception.code)
            self.assertFalse(any(self.base.glob('parent-legal*')))

    def test_same_clean_head_and_wheels_produce_identical_self_verified_release(self):
        first = self.build("first")
        second = self.build("second")
        self.assertEqual(first["archive_sha256"], second["archive_sha256"])
        self.assertEqual(first["manifest_sha256"], second["manifest_sha256"])
        verified = setup.verify_release(
            archive=Path(first["archive"]), manifest=Path(first["manifest"]),
            archive_sha256=first["archive_sha256"], manifest_sha256=first["manifest_sha256"],
        )
        names = {name for name, _, _ in verified.files}
        self.assertIn("app/getzilla_factory/server.py", names)
        self.assertIn("site-packages/demo/__init__.py", names)
        self.assertEqual({"legal/project/LICENSE"}, {name for name in names if name.startswith("legal/")})

    def test_output_stem_with_dotted_version_is_preserved(self):
        result = self.build("factory-1.2.3")
        self.assertEqual(Path(result["archive"]).name, "factory-1.2.3.zip")
        self.assertEqual(Path(result["manifest"]).name, "factory-1.2.3.manifest.json")

    def test_dirty_source_missing_extra_or_tampered_wheel_has_zero_output(self):
        (self.repo / "dirty").write_text("untracked")
        with self.assertRaises(setup.InstallerError) as error:
            self.build("dirty")
        self.assertEqual(error.exception.code, "SOURCE_NOT_CLEAN")
        self.assertFalse((self.base / "dirty.zip").exists())
        (self.repo / "dirty").unlink()
        extra = self.wheelhouse / "extra.whl"
        extra.write_bytes(b"extra")
        with self.assertRaises(setup.InstallerError) as error:
            self.build("extra")
        self.assertEqual(error.exception.code, "WHEELHOUSE_MISMATCH")
        extra.unlink()
        wheel = next(self.wheelhouse.iterdir())
        wheel.write_bytes(wheel.read_bytes() + b"tamper")
        with self.assertRaises(setup.InstallerError) as error:
            self.build("tamper")
        self.assertEqual(error.exception.code, "WHEEL_DIGEST_MISMATCH")

    def test_wrong_head_inventory_drift_missing_and_symlink_wheels_fail_closed(self):
        with self.assertRaises(setup.InstallerError) as error:
            self.builder.build_release(repository=self.repo, expected_head="f" * 40,
                                       wheelhouse=self.wheelhouse, inventory=self.inventory,
                                       output=self.base / "wrong-head", product_version="1.2.3",
                                       enforce_host=False, target_environment=self.environment)
        self.assertEqual(error.exception.code, "SOURCE_HEAD_MISMATCH")
        value = json.loads(self.inventory.read_text())
        value["wheels"][0]["version"] = "9.9.9"
        self.inventory.write_text(json.dumps(value))
        with self.assertRaises(setup.InstallerError) as error:
            self.build("drift")
        self.assertEqual(error.exception.code, "WHEEL_INVENTORY_DRIFT")
        value["wheels"][0]["version"] = "1.0.0"
        self.inventory.write_text(json.dumps(value))
        wheel = next(self.wheelhouse.iterdir())
        parked = self.base / wheel.name
        wheel.rename(parked)
        with self.assertRaises(setup.InstallerError) as error:
            self.build("missing")
        self.assertEqual(error.exception.code, "WHEELHOUSE_MISMATCH")
        wheel.symlink_to(parked)
        with self.assertRaises(setup.InstallerError) as error:
            self.build("symlink")
        self.assertEqual(error.exception.code, "WHEELHOUSE_MISMATCH")

    def test_hostile_wheel_paths_duplicates_and_special_members_are_rejected(self):
        for name, mode in (("../escape", stat.S_IFREG | 0o644),
                           ("link", stat.S_IFLNK | 0o777)):
            wheel = self.base / (name.replace("/", "-") + ".whl")
            with zipfile.ZipFile(wheel, "w") as archive:
                info = zipfile.ZipInfo(name)
                info.create_system = 3
                info.external_attr = mode << 16
                archive.writestr(info, b"bad")
            with self.assertRaises(setup.InstallerError):
                self.builder._wheel_files(wheel)
        duplicate = self.base / "duplicate.whl"
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(duplicate, "w") as archive:
                for content in (b"one", b"two"):
                    info = zipfile.ZipInfo("same.py")
                    info.create_system = 3
                    info.external_attr = (stat.S_IFREG | 0o644) << 16
                    archive.writestr(info, content)
        with self.assertRaises(setup.InstallerError):
            self.builder._wheel_files(duplicate)

    def test_partial_publication_is_removed_and_host_gate_fails_closed(self):
        real_replace = self.builder.os.replace
        calls = 0

        def fail_second(source, target):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("simulated publication failure")
            return real_replace(source, target)

        with patch.object(self.builder.os, "replace", side_effect=fail_second):
            with self.assertRaises(setup.InstallerError) as error:
                self.build("partial")
        self.assertEqual(error.exception.code, "OUTPUT_PUBLICATION_FAILED")
        self.assertFalse(any(self.base.glob("partial*")))
        with patch.object(self.builder, "_host_environment", return_value=None):
            with self.assertRaises(setup.InstallerError) as error:
                self.builder.build_release(repository=self.repo, expected_head=self.head,
                                           wheelhouse=self.wheelhouse, inventory=self.inventory,
                                           output=self.base / "host", product_version="1.2.3")
        self.assertEqual(error.exception.code, "UNSUPPORTED_HOST")

    def test_committed_inventory_is_exactly_derived_from_uv_lock(self):
        repository = Path(__file__).resolve().parents[2]
        inventory = repository / "factory/runtime/runtime-wheels-linux-x86_64-cpython312.json"
        self.builder.validate_committed_inventory(repository / "factory/uv.lock", inventory,
                                                 target_environment=self.environment)

    def test_runtime_graph_excludes_dev_and_follows_activated_extras_and_markers(self):
        original = self.repo / 'factory/uv.lock'
        text = original.read_text().replace('dependencies = [{name = "demo"}]',
                                           'dependencies = [{name = "demo", extra = ["binary"]}]')
        text = text.replace('name = "demo"\nversion = "1.0.0"',
                            'name = "demo"\nversion = "1.0.0"\n'
                            'dependencies = [{name = "absent-on-windows", marker = "sys_platform == \'win32\'"}]')
        text += ('\n[package.optional-dependencies]\nbinary = [{name = "binary", marker = "implementation_name != \'pypy\'"}]\n'
                 '\n[[package]]\nname = "binary"\nversion = "1.0.0"\n'
                 'wheels = [{url = "https://invalid.example/binary-1.0.0-py3-none-any.whl", hash = "sha256:' + 'a' * 64 + '"}]\n'
                 '\n[[package]]\nname = "dev-only"\nversion = "9.0.0"\n')
        original.write_text(text)
        derived = self.builder.derive_inventory(original, target_environment=self.environment)
        self.assertEqual(['binary', 'demo'], [item['name'] for item in derived['wheels']])
        self.assertEqual(hashlib.sha256(original.read_bytes()).hexdigest(), derived['lock_sha256'])

    def test_runtime_graph_refuses_missing_ambiguous_unsupported_and_unresolved_wheels(self):
        lock = self.repo / 'factory/uv.lock'
        original = lock.read_text()
        cases = [
            original.replace('name = "demo"}]', 'name = "missing"}]'),
            original + '\n[[package]]\nname = "demo"\nversion = "2.0.0"\n',
            original.replace('name = "demo"}]', 'name = "demo", extra = ["missing"]}]'),
            original.replace('name = "demo"}]', 'name = "demo", marker = "platform_release == \'unknown\'"}]'),
            original.replace('name = "demo"}]', 'name = "demo", marker = "sys_platform == \'linux\' or unknown"}]'),
            original.replace('name = "demo"}]', 'name = "demo", version = "2.0.0"}]'),
            original.replace('dependencies = [{name = "demo"}]', ''),
            original.replace('-py3-none-any.whl', '-cp312-cp312-win_amd64.whl'),
            original.replace('requires-python = ">=3.12,<3.13"', 'requires-python = ">=3.13"'),
            original.replace('requires-python = ">=3.12,<3.13"', 'requires-python = 312'),
            original.replace('name = "demo"}]', 'name = "demo", marker = "sys_platform == \'win32\'"}]'),
            original.replace('url = "https://invalid.example/demo-1.0.0-py3-none-any.whl"', 'url = 1'),
            original.replace('name = "demo"}]', 'name = "demo", marker = "python_full_version < \'3.12\'"}]'),
        ]
        for text in cases:
            with self.subTest(text=text):
                lock.write_text(text)
                with self.assertRaises(setup.InstallerError):
                    self.builder.derive_inventory(lock, target_environment=self.environment)

    def test_runtime_graph_bounds_and_lock_binding_remain_strict(self):
        lock = self.repo / 'factory/uv.lock'
        original = lock.read_text()
        for text in (original + '\n[[package]]\nname = "p"\nversion = "1"\n' * 513,
                     original.replace('dependencies = [{name = "demo"}]',
                                      'dependencies = [' + ','.join('{name = "demo"}' for _ in range(4097)) + ']')):
            with self.subTest(bytes=len(text)):
                lock.write_text(text)
                with self.assertRaises(setup.InstallerError):
                    self.builder.derive_inventory(lock, target_environment=self.environment)
        lock.write_text(original + '\n')
        with self.assertRaises(setup.InstallerError) as error:
            self.builder.validate_committed_inventory(lock, self.inventory, target_environment=self.environment)
        self.assertEqual('WHEEL_INVENTORY_DRIFT', error.exception.code)

    def test_current_runtime_wheels_match_twenty_committed_records(self):
        repository = Path(__file__).resolve().parents[2]
        previous = json.loads((repository / 'factory/runtime/runtime-wheels-linux-x86_64-cpython312.json').read_text())
        self.assertEqual(20, len(previous['wheels']))
        self.assertEqual(previous['wheels'], self.builder.derive_inventory(repository / 'factory/uv.lock',
                                                                        target_environment=self.environment)['wheels'])

    def test_public_enforced_build_includes_patch_required_wheel_and_reports_actual_target(self):
        lock = self.patch_lock("python_full_version >= '3.12.1'")
        for version in ('3.12.3', '3.12.12'):
            with self.subTest(version=version), self.admitted_target(version) as environment:
                self.inventory.write_text(json.dumps(self.builder.derive_inventory(lock)))
                result = self.builder.build_release(repository=self.repo, expected_head=self.head,
                    wheelhouse=self.wheelhouse, inventory=self.inventory, output=self.base / version,
                    product_version='1.2.3', enforce_host=True)
                with zipfile.ZipFile(result['archive']) as archive:
                    self.assertIn('site-packages/patch_required/__init__.py', archive.namelist())
                self.assertEqual(environment, result['target_environment'])

    def test_public_enforced_build_refuses_missing_patch_wheel_and_unknown_target(self):
        lock = self.patch_lock("python_full_version > '3.12.0'", include_wheel=False)
        with self.admitted_target():
            self.inventory.write_text(json.dumps(self.builder.derive_inventory(lock)))
            with self.assertRaises(setup.InstallerError) as error:
                self.builder.build_release(repository=self.repo, expected_head=self.head,
                    wheelhouse=self.wheelhouse, inventory=self.inventory, output=self.base / 'missing',
                    product_version='1.2.3', enforce_host=True)
            self.assertEqual('WHEELHOUSE_MISMATCH', error.exception.code)
        for version in ('3.12.unknown', '3.12', '3.11.15', '3.13.0'):
            with self.subTest(version=version), self.admitted_target(version):
                with self.assertRaises(setup.InstallerError):
                    self.builder.derive_inventory(lock)

    def test_lock_python_requirement_uses_admitted_patch_not_a_guessed_minimum(self):
        lock = self.patch_lock("python_full_version > '3.12.0'", requirement='>=3.12.1,<3.13')
        with self.admitted_target('3.12.3'):
            derived = self.builder.derive_inventory(lock)
            self.assertEqual(['demo', 'patch-required'], [item['name'] for item in derived['wheels']])
        lock.write_text(lock.read_text().replace('>=3.12.1,<3.13', '<3.12.3'))
        with self.admitted_target('3.12.3'), self.assertRaises(setup.InstallerError):
            self.builder.derive_inventory(lock)


    def test_explicit_target_must_be_complete_supported_and_match_enforced_host(self):
        lock = self.repo / 'factory/uv.lock'
        for environment in (None, {}, {**self.environment, 'python_full_version': '3.11.15'},
                            {**self.environment, 'python_full_version': '3.12.unknown'},
                            {**self.environment, 'python_version': '3.13'},
                            {**self.environment, 'implementation_name': 'pypy'},
                            {**self.environment, 'platform_machine': 'aarch64'},
                            {**self.environment, 'extra-field': 'unknown'}):
            with self.subTest(environment=environment), patch.object(self.builder, '_host_environment', return_value=None):
                with self.assertRaises(setup.InstallerError):
                    self.builder.derive_inventory(lock, target_environment=environment)
        with self.admitted_target('3.12.12'):
            with self.assertRaises(setup.InstallerError) as error:
                self.builder.build_release(repository=self.repo, expected_head=self.head,
                    wheelhouse=self.wheelhouse, inventory=self.inventory, output=self.base / 'mismatch',
                    product_version='1.2.3', enforce_host=True, target_environment=self.environment)
            self.assertEqual('TARGET_PROFILE_MISMATCH', error.exception.code)
            self.assertFalse(any(self.base.glob('mismatch*')))
        with patch.object(self.builder, '_host_environment', return_value=None):
            with self.assertRaises(setup.InstallerError) as error:
                self.builder.build_release(repository=self.repo, expected_head=self.head,
                    wheelhouse=self.wheelhouse, inventory=self.inventory, output=self.base / 'unknown-explicit',
                    product_version='1.2.3', enforce_host=True, target_environment=self.environment)
            self.assertEqual('UNSUPPORTED_HOST', error.exception.code)
            self.assertFalse(any(self.base.glob('unknown-explicit*')))
        result = self.build('explicit-diagnostic')
        self.assertFalse(result['host_enforced'])
        self.assertEqual(self.environment, result['target_environment'])

    def test_unknown_target_probe_records_refuse_instead_of_omitting_edges(self):
        original_run = subprocess.run
        records = ('{', '{}', json.dumps({'environment': self.environment, 'pointer_bits': 32, 'releaselevel': 'final'}),
                   json.dumps({'environment': self.environment, 'pointer_bits': 64, 'releaselevel': 'candidate'}),
                   json.dumps({'environment': self.environment, 'pointer_bits': True, 'releaselevel': 'final'}))
        for record in records:
            def run(command, *args, **kwargs):
                if command[0] == '/usr/bin/python3.12':
                    return subprocess.CompletedProcess(command, 0, record, '')
                return original_run(command, *args, **kwargs)
            with self.subTest(record=record), self.admitted_target(), patch.object(self.builder.subprocess, 'run', side_effect=run):
                with self.assertRaises(setup.InstallerError) as error:
                    self.builder.build_release(repository=self.repo, expected_head=self.head,
                        wheelhouse=self.wheelhouse, inventory=self.inventory, output=self.base / 'unknown',
                        product_version='1.2.3', enforce_host=True)
                self.assertEqual('UNSUPPORTED_HOST', error.exception.code)


if __name__ == "__main__":
    unittest.main()
