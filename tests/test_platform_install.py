"""Platform acceptance observations never replace independent security admission."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import tempfile
import time
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla import platform_install as acceptance  # noqa: E402


class PlatformContractTests(unittest.TestCase):
    def test_supported_matrix_requires_five_native_pairs_and_explicit_windows_arm_gap(self):
        cells = acceptance.load_matrix(ROOT)
        self.assertEqual({c['id'] for c in cells if c['required']},
                         {'linux-x64', 'linux-arm64', 'macos-x64', 'macos-arm64', 'windows-x64'})
        arm = next(c for c in cells if c['id'] == 'windows-arm64')
        self.assertFalse(arm['supported'])
        self.assertFalse(arm['required'])
        self.assertIn('OpenGrep', arm['reason'])

    def test_architecture_must_be_observed_not_inferred_from_requested_runner(self):
        self.assertEqual(acceptance.native_platform('Darwin', 'arm64'), ('macos', 'arm64'))
        self.assertEqual(acceptance.native_platform('Windows', 'AMD64'), ('windows', 'x64'))
        with self.assertRaises(ValueError):
            acceptance.native_platform('Linux', 'mips64')

    def test_malformed_support_inventory_cannot_establish_required_platforms(self):
        original = json.loads((ROOT/acceptance.MATRIX_PATH).read_text())
        for field, value in [('schema_version', True), ('cells', [1]*6)]:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                path = root/acceptance.MATRIX_PATH
                path.parent.mkdir(parents=True)
                broken = copy.deepcopy(original)
                broken[field] = value
                path.write_text(json.dumps(broken))
                with self.assertRaises(ValueError):
                    acceptance.load_matrix(root)

    def test_support_inventory_refuses_a_link_instead_of_reading_another_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            outside = root/'outside.json'
            outside.write_bytes((ROOT/acceptance.MATRIX_PATH).read_bytes())
            path = root/acceptance.MATRIX_PATH
            path.parent.mkdir(parents=True)
            try:
                path.symlink_to(outside)
            except (OSError, NotImplementedError):
                self.skipTest('symbolic link fixture not available')
            with self.assertRaises(ValueError):
                acceptance.load_matrix(root)

    def record(self):
        record = {'schema': 'getzilla-platform-install-v1', 'cell': 'linux-x64',
                'repository': 'example-owner/example-repo',
                'os': 'linux', 'arch': 'x64', 'head': 'a' * 40, 'tree': 'b' * 40,
                'head_after': 'a' * 40, 'tree_after': 'b' * 40, 'source_clean': True,
                'run_id': '123', 'run_attempt': '2', 'authority': 'observations-only',
                'stable': {'tag': 'v2.3.0', 'commit': '2bb417431f1e4b9494e4af71ebf27adb1d04d898',
                           'tag_object': '815aeabc5d215d65e72651692a6457920de9fa71'},
                'scenarios': {name: {'status': 'pass', 'installed_head': 'a' * 40,
                                    'version': '2.3.1', 'cli_sha256': 'c' * 64,
                                    'managed_sha256': 'e' * 64,
                                    'from_head': '2bb417431f1e4b9494e4af71ebf27adb1d04d898', 'from_version': '2.3.0',
                                    'from_project_version': '2.3.0',
                                    'cli_exit': 0, 'doctor_exit': 0, 'installer_exit': 0,
                                    'user_preserved': True, 'settings_preserved': True,
                                    'agents': ['qwen'], 'update_exit': 0, 'logs_complete': True}
                              for name in ('clean', 'upgrade')}}
        record['commands'] = []
        record['scenarios']['upgrade'].update(baseline_mode='stock-installer-create', historical_installer_create='pass')
        for index, checks in enumerate(record['scenarios'].values(), 1):
            log = f'{index:03d}.log'
            checks['logs'] = [log]
            record['commands'].append({'exit': 0, 'logs_complete': True, 'cleanup_confirmed': True,
                'log': log, 'observed_bytes': 1, 'retained_bytes': 1, 'dropped_bytes': 0,
                'seconds': 0.01, 'sha256': hashlib.sha256(b'x').hexdigest()})
        return record

    def validate(self, records, job_result='success'):
        return acceptance.validate_results(records, matrix=acceptance.load_matrix(ROOT),
                 required=['linux-x64'], head='a' * 40, tree='b' * 40, run_id='123', run_attempt='2',
                 repository='example-owner/example-repo',
                 version='2.3.1', cli_sha256='c' * 64, managed_sha256='e' * 64,
                 stable=self.record()['stable'], job_result=job_result)

    def test_missing_failed_skipped_duplicate_or_substituted_evidence_blocks_aggregate(self):
        good = self.record()
        self.assertEqual(self.validate([good]), [])
        self.assertTrue(self.validate([]))
        self.assertTrue(self.validate([good, good]))
        for result in ('skipped', 'cancelled', 'failure', 'missing'):
            self.assertTrue(self.validate([good], result))
        for field, value in [('head', 'd' * 40), ('tree', 'd' * 40), ('run_attempt', '1'),
                             ('repository', 'another-owner/another-repo'),
                             ('arch', 'arm64'), ('authority', 'security-approved'),
                             ('error', 'producer failed'), ('source_clean', False), ('head_after', 'd' * 40)]:
            bad = copy.deepcopy(good)
            bad[field] = value
            self.assertTrue(self.validate([bad]), field)
        for field, value in [('status', 'skipped'), ('installer_exit', 1), ('doctor_exit', 1),
                             ('logs_complete', False), ('user_preserved', False),
                             ('settings_preserved', False), ('agents', ['codex']),
                             ('baseline_mode', 'restored-v230-artifact'),
                             ('historical_installer_create', 'unsupported'), ('from_project_version', '2.3.1'),
                             ('installed_head', 'd' * 40), ('cli_sha256', 'd' * 64)]:
            bad = copy.deepcopy(good)
            bad['scenarios']['upgrade'][field] = value
            self.assertTrue(self.validate([bad]), field)

    def test_json_result_reader_refuses_duplicate_keys_and_oversized_input(self):
        with self.assertRaises(ValueError):
            acceptance.decode_result(b'{"cell":"linux-x64","cell":"windows-x64"}')
        with self.assertRaises(ValueError):
            acceptance.decode_result(b' ' * 65537)
        with self.assertRaises(ValueError):
            acceptance.decode_result(b'{"seconds":1e999}')
        self.assertEqual(acceptance.decode_result(json.dumps(self.record()).encode()), self.record())


class ActualCommandTests(unittest.TestCase):
    def test_cli_checks_native_identity_and_refuses_local_live_installer_before_writes(self):
        script = ROOT/'scripts/getzilla_platform_install.py'
        matrix = subprocess.run([sys.executable, str(script), '--matrix'], capture_output=True,
                                text=True, timeout=5)
        self.assertEqual(matrix.returncode, 0, matrix.stderr)
        self.assertEqual(len(json.loads(matrix.stdout)['include']), 5)
        unknown = subprocess.run([sys.executable, str(script), '--check-platform', 'unknown'],
                                 capture_output=True, text=True, timeout=5)
        self.assertEqual(unknown.returncode, 1)
        self.assertNotIn('Traceback', unknown.stdout+unknown.stderr)
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)/'absent'
            environment = dict(os.environ)
            environment.pop('GITHUB_ACTIONS', None)
            live = subprocess.run([sys.executable, str(script), '--cell', 'linux-x64',
                                   '--workspace', str(workspace), '--head', 'a'*40],
                                  env=environment, capture_output=True, text=True, timeout=5)
            self.assertEqual(live.returncode, 1)
            self.assertFalse(workspace.exists())
            self.assertEqual(json.loads(live.stdout)['authority'], 'observations-only')

    def test_real_producer_is_drained_past_report_quota_without_false_complete_evidence(self):
        from getzilla.platform_acceptance import run_command
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = run_command([sys.executable, '-c', "import os; os.write(1,b'x'*200000)"],
                                 cwd=root, log=root/'output.log', timeout=5, quota=1024)
            self.assertEqual(result['exit'], 0)
            self.assertEqual(result['observed_bytes'], 200000)
            self.assertEqual((root/'output.log').stat().st_size, 1024)
            self.assertFalse(result['logs_complete'])

    def test_total_deadline_still_applies_when_child_closes_its_output(self):
        from getzilla.platform_acceptance import run_command
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            started = time.monotonic()
            result = run_command([sys.executable, '-c', 'import os,time; os.close(1); os.close(2); time.sleep(2)'],
                                 cwd=root, log=root/'output.log', timeout=0.1)
            self.assertEqual(result['exit'], 124)
            self.assertLess(time.monotonic()-started, 1.5)


class CollectedArtifactTests(unittest.TestCase):
    """Synthetic artifact controls exercise the real CLI; they are not native results."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.root.chmod(0o700)
        self.head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
        tree = subprocess.check_output(['git', 'rev-parse', 'HEAD^{tree}'], cwd=ROOT, text=True).strip()
        self.environment = {**os.environ, 'GITHUB_REPOSITORY': 'example-owner/example-repo',
                            'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '2'}
        for cell in (c for c in acceptance.load_matrix(ROOT) if c['required']):
            record = PlatformContractTests().record()
            record.update(cell=cell['id'], os=cell['os'], arch=cell['arch'], head=self.head,
                          tree=tree, head_after=self.head, tree_after=tree, commands=[])
            if cell['os'] == 'macos':
                record['scenarios']['upgrade'].update(baseline_mode='restored-v230-artifact',
                    historical_installer_create='unsupported', historical_bootstrap_exit=0,
                    historical_baseline_apply_exit=0)
            folder = self.root / cell['id']
            folder.mkdir()
            for index, (name, scenario) in enumerate(record['scenarios'].items(), 1):
                log = f'{index:03}.log'
                content = f'synthetic {name} artifact control\n'.encode()
                (folder / log).write_bytes(content)
                record['commands'].append({'log': log, 'exit': 0, 'logs_complete': True,
                    'cleanup_confirmed': True, 'observed_bytes': len(content), 'retained_bytes': len(content),
                    'dropped_bytes': 0, 'seconds': 0.01, 'sha256': hashlib.sha256(content).hexdigest()})
                scenario.update(installed_head=self.head, version=(ROOT/'VERSION').read_text().strip(),
                    cli_sha256=hashlib.sha256((ROOT/'scripts/getzilla_cli.py').read_bytes()).hexdigest(),
                    managed_sha256=hashlib.sha256((ROOT/'scripts/getzilla_doctor.py').read_bytes()).hexdigest(),
                    logs=[log])
            (folder/'result.json').write_text(json.dumps(record))
        self.folder = self.root/'linux-x64'

    def run_aggregate(self, profile=None):
        arguments = ['--aggregate', str(self.root), '--head', self.head, '--job-result', 'success']
        if profile is not None:
            arguments += ['--profile', profile]
        result = subprocess.run([sys.executable, str(ROOT/'scripts/getzilla_platform_install.py'), *arguments],
                    cwd=ROOT, env=self.environment, capture_output=True, text=True, timeout=10)
        self.assertNotIn('Traceback', result.stderr + result.stdout)
        self.assertEqual(json.loads(result.stdout)['authority'], 'observations-only')
        return result

    def change_record(self, mutate):
        path = self.folder/'result.json'
        record = json.loads(path.read_text())
        mutate(record)
        path.write_text(json.dumps(record))

    def test_matching_bounded_regular_logs_pass_structural_control(self):
        result = self.run_aggregate()
        self.assertEqual(result.returncode, 0, result.stdout)

    @unittest.skipUnless(importlib.util.find_spec('yaml'), 'requires YAML')
    def test_own_macos_witness_upload_is_separate_from_strict_installer_artifacts(self):
        import fnmatch
        import glob
        from unittest.mock import patch
        import yaml
        document = yaml.safe_load((ROOT / '.github/workflows/getzilla.yml').read_text())
        steps = document['jobs']['platform-install']['steps']
        probe = next(s for s in steps if s.get('name') == 'Observe canonical public fixture startup on macOS')
        installer = next(s for s in steps if s.get('name') == 'Retain actual install and upgrade observations')
        witness = next((s for s in steps if s.get('name') == 'Retain canonical public fixture startup observations'), None)
        download = next(s for s in document['jobs']['platform-install-results']['steps']
                        if s.get('name') == "Download only this run and attempt's Linux platform observations")
        with tempfile.TemporaryDirectory() as temporary:
            runner = Path(temporary)

            def expand(value, cell):
                for key, replacement in {'runner.temp': str(runner), 'matrix.id': cell,
                        'github.run_id': '123', 'github.run_attempt': '2'}.items():
                    value = value.replace('${{ ' + key + ' }}', replacement)
                return value

            artifacts = runner / 'artifacts'
            artifacts.mkdir()
            for cell in (c['id'] for c in acceptance.load_matrix(ROOT) if c['required']):
                shutil.copytree(self.root / cell, runner / ('platform-' + cell))
                if cell.startswith('macos-'):
                    def public_child(command, **kwargs):
                        kwargs['stdout'].write(b'public synthetic fixture witness\n')
                        return subprocess.CompletedProcess(command, 0)
                    with patch.dict(os.environ, {'RUNNER_TEMP': str(runner), 'GETZILLA_PLATFORM_CELL': cell}, clear=True), \
                            patch.object(subprocess, 'run', side_effect=public_child), self.assertRaises(SystemExit) as stopped:
                        exec(compile(probe['run'], '<own-workflow-public-probe>', 'exec'), {})
                    self.assertEqual(stopped.exception.code, 0)
                folder = artifacts / expand(installer['with']['name'], cell)
                folder.mkdir()
                for pattern in installer['with']['path'].splitlines():
                    for name in glob.glob(expand(pattern, cell)):
                        shutil.copyfile(name, folder / Path(name).name)
                if cell.startswith('macos-') and witness:
                    folder = artifacts / expand(witness['with']['name'], cell)
                    folder.mkdir()
                    log = Path(expand(witness['with']['path'], cell))
                    self.assertTrue(log.is_file(), 'witness upload path was not produced')
                    shutil.copyfile(log, folder / 'public-fixture-startup.log')
            collected = runner / 'collected'
            collected.mkdir()
            pattern = expand(download['with']['pattern'], 'unused')
            for folder in artifacts.iterdir():
                if fnmatch.fnmatchcase(folder.name, pattern):
                    shutil.copytree(folder, collected / folder.name)
            original = self.root
            self.root = collected
            try:
                result = self.run_aggregate('linux')
                self.assertEqual(result.returncode, 0, result.stdout)
                self.assertIsNotNone(witness)
                self.assertEqual(witness['if'], "${{ always() && matrix.os == 'macos' }}")
                self.assertEqual(witness['uses'], installer['uses'])
                self.assertEqual(witness['with']['retention-days'], 30)
                self.assertEqual(witness['with']['if-no-files-found'], 'error')
                self.assertEqual(len(list(collected.iterdir())), 2)
                for cell in ('macos-x64', 'macos-arm64'):
                    name = expand(witness['with']['name'], cell)
                    self.assertFalse(fnmatch.fnmatchcase(name, pattern))
                    self.assertEqual((artifacts / name / 'public-fixture-startup.log').read_bytes(),
                                     b'public synthetic fixture witness\n')
                folder = collected / expand(installer['with']['name'], 'linux-x64')
                log = folder / '001.log'
                raw = log.read_bytes()
                for mutation in ('missing', 'corrupt', 'extra', 'nested', 'old-co-location'):
                    with self.subTest(mutation=mutation):
                        if mutation == 'missing':
                            log.unlink()
                        elif mutation == 'corrupt':
                            log.write_bytes(b'changed')
                        elif mutation == 'nested':
                            (folder / 'nested').mkdir()
                            (folder / 'nested/extra.log').write_bytes(b'x')
                        else:
                            (folder / ('public-fixture-startup.log' if mutation == 'old-co-location' else 'extra.log')).write_bytes(b'x')
                        refused = self.run_aggregate('linux')
                        self.assertEqual(refused.returncode, 1, refused.stdout)
                        self.assertIn('platform', json.loads(refused.stdout)['error'])
                        for extra in ('extra.log', 'public-fixture-startup.log'):
                            (folder / extra).unlink(missing_ok=True)
                        shutil.rmtree(folder / 'nested', ignore_errors=True)
                        log.write_bytes(raw)
            finally:
                self.root = original

    def test_missing_or_changed_log_refuses_despite_complete_claim(self):
        log = self.folder/'001.log'
        content = log.read_bytes()
        log.unlink()
        self.assertEqual(self.run_aggregate().returncode, 1)
        log.write_bytes(content + b'tampered')
        self.assertEqual(self.run_aggregate().returncode, 1)
        log.write_bytes(b'x' * len(content))
        self.assertEqual(self.run_aggregate().returncode, 1)

    def test_empty_duplicate_unbound_or_incomplete_commands_refuse(self):
        path = self.folder/'result.json'
        original = path.read_bytes()
        mutations = [lambda r: r.update(commands=[]),
                     lambda r: r.update(cell=[]),
                     lambda r: r['commands'].append(r['commands'][0]),
                     lambda r: r['commands'][0].update(cleanup_confirmed=False),
                     lambda r: r['commands'][0].update(observed_bytes=True),
                     lambda r: r['commands'][0].update(seconds=10**1000),
                     lambda r: r['commands'][0].update(dropped_bytes=1),
                     lambda r: r['commands'][0].pop('sha256'),
                     lambda r: r['scenarios']['clean'].update(logs=[]),
                     lambda r: r['scenarios']['clean'].update(logs=['099.log']),
                     lambda r: r['scenarios']['upgrade'].update(logs=['001.log'])]
        for mutate in mutations:
            path.write_bytes(original)
            self.change_record(mutate)
            with self.subTest(mutation=mutate):
                self.assertEqual(self.run_aggregate().returncode, 1)

    def test_traversal_absolute_and_outside_log_paths_refuse(self):
        path = self.folder/'result.json'
        original = path.read_bytes()
        for name in ('../001.log', '/tmp/001.log', 'nested/001.log', r'C:\outside.log', r'..\001.log'):
            path.write_bytes(original)
            self.change_record(lambda r: r['commands'][0].update(log=name))
            with self.subTest(path=name):
                self.assertEqual(self.run_aggregate().returncode, 1)

    def test_linked_log_and_linked_artifact_directory_refuse(self):
        log = self.folder/'001.log'
        other = self.root.parent/(self.root.name+'-outside.log')
        self.addCleanup(lambda: other.unlink(missing_ok=True))
        other.write_bytes(log.read_bytes())
        log.unlink()
        try:
            log.symlink_to(other)
        except (OSError, NotImplementedError):
            self.skipTest('symbolic link fixture unavailable')
        self.assertEqual(self.run_aggregate().returncode, 1)
        log.unlink()
        log.write_bytes(other.read_bytes())
        other.unlink()
        moved = self.root.parent/(self.root.name+'-outside')
        self.folder.rename(moved)
        self.addCleanup(shutil.rmtree, moved)
        self.folder.symlink_to(moved, target_is_directory=True)
        self.assertEqual(self.run_aggregate().returncode, 1)

    def test_hard_linked_log_refuses_even_with_matching_bytes(self):
        log = self.folder/'001.log'
        other = self.root.parent/(self.root.name+'-hardlink.log')
        self.addCleanup(lambda: other.unlink(missing_ok=True))
        log.rename(other)
        try:
            os.link(other, log)
        except (OSError, NotImplementedError):
            self.skipTest('hard link fixture unavailable')
        self.assertEqual(self.run_aggregate().returncode, 1)

    def test_oversized_log_and_extra_artifacts_refuse_with_bounded_output(self):
        content = (self.folder/'001.log').read_bytes()
        with (self.folder/'001.log').open('r+b') as handle:
            handle.truncate(8*1024*1024+1)
        result = self.run_aggregate()
        self.assertEqual(result.returncode, 1)
        self.assertLess(len(result.stdout), 1024)
        (self.folder/'001.log').write_bytes(content)
        (self.root/'unexpected').mkdir()
        self.assertEqual(self.run_aggregate().returncode, 1)

    def test_empty_required_output_and_command_resource_budgets_refuse(self):
        path = self.folder/'result.json'
        original = path.read_bytes()
        self.change_record(lambda r: r['commands'][0].update(
            observed_bytes=0, retained_bytes=0, sha256=hashlib.sha256(b'').hexdigest()))
        (self.folder/'001.log').write_bytes(b'')
        self.assertEqual(self.run_aggregate().returncode, 1)
        for count, size, message in ((129, 1, 'command evidence'), (9, 8*1024*1024, 'byte budget')):
            path.write_bytes(original)
            def enlarge(record):
                template = record['commands'][0]
                record['commands'] = [{**template, 'log': f'{i:03d}.log', 'observed_bytes': size,
                                       'retained_bytes': size} for i in range(1, count+1)]
            self.change_record(enlarge)
            result = self.run_aggregate()
            self.assertEqual(result.returncode, 1)
            self.assertIn(message, result.stdout)


class LinuxProfileTests(unittest.TestCase):
    """Pure synthetic observations; never launch a native acceptance cell."""
    setUp = CollectedArtifactTests.setUp

    def invoke(self, *arguments):
        return subprocess.run([sys.executable, str(ROOT/'scripts/getzilla_platform_install.py'),
                               *arguments], cwd=ROOT, env=self.environment,
                              capture_output=True, text=True, timeout=5)

    def test_profile_is_closed_and_default_matrix_stays_all(self):
        default = self.invoke('--matrix')
        self.assertEqual(default.returncode, 0)
        self.assertEqual({c['id'] for c in json.loads(default.stdout)['include']},
                         {'linux-x64', 'linux-arm64', 'macos-x64', 'macos-arm64', 'windows-x64'})
        linux = self.invoke('--matrix', '--profile', 'linux')
        self.assertEqual(linux.returncode, 0)
        self.assertEqual({c['id'] for c in json.loads(linux.stdout)['include']},
                         {'linux-x64', 'linux-arm64'})
        for arguments in (('--matrix','--profile',''), ('--matrix','--profile','unknown'),
                          ('--check-platform','linux-x64','--profile','all'),
                          ('--cell','linux-x64','--profile','linux'),
                          ('--restore-stable-payload','absent','--profile','linux')):
            with self.subTest(arguments=arguments):
                self.assertNotEqual(self.invoke(*arguments).returncode, 0)

    def test_linux_aggregate_requires_real_complete_current_records_and_success(self):
        for cell in ('macos-x64', 'macos-arm64', 'windows-x64'):
            shutil.rmtree(self.root/cell)
        arguments = ('--aggregate',str(self.root),'--head',self.head,'--profile','linux')
        good = self.invoke(*arguments, '--job-result','success')
        self.assertEqual(good.returncode, 0)
        report = json.loads(good.stdout)
        self.assertEqual(report['profile'], 'linux')
        self.assertEqual(report['required_cells'], 2)
        self.assertEqual(set(report['required_platforms']), {'linux-x64','linux-arm64'})
        self.assertNotEqual(self.invoke('--aggregate',str(self.root),'--head',self.head,
                                        '--job-result','success').returncode, 0)
        for state in ('failure','skipped','cancelled','missing'):
            self.assertNotEqual(self.invoke(*arguments,'--job-result',state).returncode, 0)
        path = self.folder/'result.json'
        original = path.read_bytes()
        record = json.loads(original)
        record['head'] = 'd'*40
        path.write_text(json.dumps(record))
        self.assertNotEqual(self.invoke(*arguments,'--job-result','success').returncode, 0)
        path.write_bytes(original)
        shutil.copytree(self.folder, self.root/'unrequested-os')
        self.assertNotEqual(self.invoke(*arguments,'--job-result','success').returncode, 0)
        shutil.rmtree(self.root/'unrequested-os')
        shutil.rmtree(self.folder)
        self.assertNotEqual(self.invoke(*arguments,'--job-result','success').returncode, 0)

    @unittest.skipUnless(importlib.util.find_spec('yaml'), 'requires YAML')
    def test_workflow_binds_the_same_linux_profile_to_matrix_and_aggregate(self):
        import ast
        import fnmatch
        import shlex
        import yaml
        def contract(raw):
            jobs = yaml.safe_load(raw)['jobs']
            steps = jobs['platform-plan']['steps']
            run = next(step['run'] for step in steps if step.get('id') == 'inventory')
            matrix_line = next(line.strip() for line in run.splitlines() if line.strip().startswith('matrix=$('))
            argv = shlex.split(matrix_line[len('matrix=$('):-1])
            self.assertEqual(argv, ['python','scripts/getzilla_platform_install.py','--matrix','--profile','linux'])
            self.assertIn('needs.platform-plan.outputs.matrix', jobs['platform-install']['strategy']['matrix'])
            aggregate = jobs['platform-install-results']
            download = next(step for step in aggregate['steps'] if 'download-artifact@' in step.get('uses',''))
            pattern = download['with']['pattern']
            self.assertTrue(fnmatch.fnmatchcase('getzilla-platform-linux-x64-123-2',
                pattern.replace('${{ github.run_id }}','123').replace('${{ github.run_attempt }}','2')))
            self.assertFalse(fnmatch.fnmatchcase('getzilla-platform-macos-x64-123-2',
                pattern.replace('${{ github.run_id }}','123').replace('${{ github.run_attempt }}','2')))
            step = next(step for step in aggregate['steps'] if '--aggregate' in step.get('run',''))
            calls = [node for node in ast.walk(ast.parse(step['run'])) if isinstance(node,ast.Call)
                     and isinstance(node.func,ast.Attribute) and node.func.attr=='call']
            self.assertEqual(len(calls),1)
            arguments = calls[0].args[0].elts
            constants = [node.value if isinstance(node,ast.Constant) else None for node in arguments]
            offset = constants.index('--profile')
            self.assertEqual(constants[offset+1],'linux')
            self.assertIn('--job-result', constants)
            self.assertEqual(step['env']['GETZILLA_PLATFORM_JOB_RESULT'], '${{ needs.platform-install.result }}')
            self.assertEqual(jobs['linux']['needs'], 'platform-install-results')
            gate = next(step for step in jobs['linux']['steps'] if 'GETZILLA_PLATFORM_RESULT' in step.get('env',{}))
            self.assertEqual(gate['env']['GETZILLA_PLATFORM_RESULT'], '${{ needs.platform-install-results.result }}')
            return argv
        # Frozen pre-refinement workflow is a concrete negative consumer contrast.
        old = subprocess.check_output(['git','show','d29da63f4de9dedd986e40cfc1b5554950a8749a:.github/workflows/getzilla.yml'],cwd=ROOT)
        with self.assertRaises(AssertionError):
            contract(old)
        argv = contract((ROOT/'.github/workflows/getzilla.yml').read_bytes())
        produced = self.invoke(*argv[2:])
        self.assertEqual(produced.returncode,0)
        self.assertEqual({item['id'] for item in json.loads(produced.stdout)['include']}, {'linux-x64','linux-arm64'})
