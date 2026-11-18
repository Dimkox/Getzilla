"""Bounded publisher-build controls; no network, backend or installer effects."""
import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'.getzilla'))
from getzilla import managed_pyyaml


class PyYamlBuildTests(unittest.TestCase):
    def setUp(self):
        scratch = Path(__file__).resolve().parents[1]/'.getzilla/runtime/scratch'
        self.owned = tempfile.TemporaryDirectory(prefix='owned-pyyaml-', dir=scratch)
        self.addCleanup(self.owned.cleanup)
        self.root = Path(self.owned.name)
        self.commands = []
        self.corrupt_tool = self.fail_build = False
        self.project = ('[build-system]\nrequires = ["setuptools", "Cython; python_version < \'3.13\'", '
                        '"Cython>=3.0; python_version >= \'3.13\'"]\nbackend-path = ["packaging"]\n'
                        'build-backend = "_pyyaml_pep517"\n')
        out = io.BytesIO()
        with tarfile.open(fileobj=out, mode='w:gz') as archive:
            for name, body in {'pyproject.toml': self.project.encode(), 'setup.py': b'# inert owned source',
                               'packaging/_pyyaml_pep517.py': b'# inert', 'lib/yaml/__init__.py': b'# inert'}.items():
                info = tarfile.TarInfo('pyyaml-6.0.3/'+name)
                info.size = len(body)
                archive.addfile(info, io.BytesIO(body))
        self.source = out.getvalue()

    def fetch(self, url):
        prefix = 'https://pypi.org/pypi/'
        if url == prefix+'bandit/json':
            return json.dumps({'info': {'name': 'bandit'}, 'releases': {'1.9.4': [{'yanked': False}]}}).encode()
        if url == prefix+'bandit/1.9.4/json':
            return json.dumps({'info': {'name': 'bandit', 'version': '1.9.4', 'requires_dist': ['PyYAML>=5.3.1']},
                'urls': [{'filename': 'bandit-1.9.4-py3-none-any.whl',
                          'url': 'https://files.pythonhosted.org/packages/bandit-1.9.4-py3-none-any.whl',
                          'packagetype': 'bdist_wheel', 'yanked': False,
                          'digests': {'sha256': hashlib.sha256(b'inert bandit wheel').hexdigest()}}]}).encode()
        if url == 'https://files.pythonhosted.org/packages/bandit-1.9.4-py3-none-any.whl':
            return b'inert bandit wheel'
        if url == prefix+'PyYAML/json':
            return json.dumps({'info': {'name': 'PyYAML'}, 'releases': {'6.0.3': [{'yanked': False}]}}).encode()
        if url == prefix+'pyyaml/6.0.3/json':
            return json.dumps({'info': {'name': 'PyYAML', 'version': '6.0.3', 'requires_python': '>=3.8'},
                'urls': [{'filename': 'pyyaml-6.0.3.tar.gz', 'url': 'https://files.pythonhosted.org/packages/pyyaml-6.0.3.tar.gz',
                          'packagetype': 'sdist', 'yanked': False, 'digests': {'sha256': hashlib.sha256(self.source).hexdigest()}}]}).encode()
        if url.endswith('pyyaml-6.0.3.tar.gz'):
            return self.source
        for name in ('setuptools', 'cython', 'wheel'):
            filename = name+'-1.0-py3-none-any.whl'
            tool_url = 'https://files.pythonhosted.org/packages/'+filename
            if url == prefix+name+'/1.0/json':
                return json.dumps({'info': {'name': name, 'version': '1.0'}, 'urls': [{'filename': filename,
                    'url': tool_url, 'packagetype': 'bdist_wheel', 'yanked': False,
                    'digests': {'sha256': hashlib.sha256(name.encode()).hexdigest()}}]}).encode()
            if url == tool_url:
                return b'changed' if self.corrupt_tool else name.encode()
        self.fail('unexpected public read: '+url)

    def checked(self, command, phase):
        self.commands.append(phase)
        if phase == 'check current PyYAML wheel compatibility':
            return subprocess.CompletedProcess(command, 0, '{"compatible": false}', '')
        if phase == 'resolve PyYAML binary build-tool closure':
            rows = [{'metadata': {'name': name, 'version': '1.0'}, 'download_info': {
                'url': 'https://files.pythonhosted.org/packages/'+name+'-1.0-py3-none-any.whl',
                'archive_info': {'hashes': {'sha256': hashlib.sha256(name.encode()).hexdigest()}}}}
                for name in ('setuptools', 'cython', 'wheel')]
            Path(command[command.index('--report')+1]).write_text(json.dumps({'install': rows}))
        if phase == 'build verified PyYAML pure wheel offline':
            self.assertEqual(self.environment['PYYAML_FORCE_LIBYAML'], '0')
            self.assertEqual(self.environment['PIP_NO_INDEX'], '1')
            self.assertIn('--without-libyaml', command[3])
            if self.fail_build:
                raise ValueError('owned backend build failed')
            (Path(command[-1])/'pyyaml-6.0.3-py3-none-any.whl').write_bytes(self.wheel())
        if phase == 'probe actual PyYAML pure wheel on managed runtime':
            return subprocess.CompletedProcess(command, 0, '{"pure": true, "safe_load": true}', '')
        return subprocess.CompletedProcess(command, 0, '', '')

    def prepare(self):
        self.environment = {'PIP_CONFIG_FILE': os.devnull}
        self.nonce = object()
        return managed_pyyaml.prepare(self.root, Path('/owned/python'), {'bandit': '1.9.4'}, fetch=self.fetch,
                                     checked=self.checked, environment=self.environment, nonce=self.nonce)

    def wheel(self, *, pure='true', native=False, version='6.0.3'):
        out = io.BytesIO()
        with zipfile.ZipFile(out, 'w') as archive:
            archive.writestr('yaml/__init__.py', "__version__ = '6.0.3'\n")
            archive.writestr('pyyaml-6.0.3.dist-info/METADATA',
                             f'Metadata-Version: 2.4\nName: PyYAML\nVersion: {version}\nRequires-Python: >=3.8\n')
            archive.writestr('pyyaml-6.0.3.dist-info/WHEEL',
                             f'Wheel-Version: 1.0\nRoot-Is-Purelib: {pure}\nTag: py3-none-any\n')
            archive.writestr('pyyaml-6.0.3.dist-info/RECORD', '')
            if native:
                archive.writestr('yaml/_yaml.so', b'not native code')
        return out.getvalue()

    def test_pure_wheel_identity_and_native_output_refusals(self):
        managed_pyyaml._validate_wheel(self.wheel(), 'pyyaml-6.0.3-py3-none-any.whl', '6.0.3')
        for kwargs in ({'pure': 'false'}, {'native': True}, {'version': '6.0.2'}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                managed_pyyaml._validate_wheel(self.wheel(**kwargs), 'pyyaml-6.0.3-py3-none-any.whl', '6.0.3')

    def test_source_digest_is_required_before_any_backend(self):
        catalog = dict(info=dict(name='PyYAML', version='6.0.3'), urls=[dict(
            filename='pyyaml-6.0.3.tar.gz', url='https://files.pythonhosted.org/packages/pyyaml-6.0.3.tar.gz',
            digests={'sha256': hashlib.sha256(b'expected').hexdigest()}, packagetype='sdist', yanked=False)])
        calls = []
        with self.assertRaisesRegex(ValueError, 'integrity'):
            managed_pyyaml._source(catalog, '6.0.3', lambda url: calls.append(url) or self.source)
        self.assertEqual(len(calls), 1)

    def test_unknown_backend_and_build_requirements_refuse(self):
        valid = {'build-system': {'requires': ['setuptools', "Cython; python_version < '3.13'",
                    "Cython>=3.0; python_version >= '3.13'"], 'backend-path': ['packaging'],
                    'build-backend': '_pyyaml_pep517'}}
        managed_pyyaml._build_system(valid)
        for key, value in [('build-backend', 'other'), ('backend-path', ['../outside']),
                           ('requires', ['setuptools', 'unreviewed-build-tool'])]:
            changed = {'build-system': dict(valid['build-system'], **{key: value})}
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'unsupported'):
                managed_pyyaml._build_system(changed)

    def test_mutable_record_or_hash_cannot_authorize_a_local_wheel(self):
        fake = dict(path='file:///owned/pyyaml.whl', sha256=hashlib.sha256(self.wheel()).hexdigest())
        with self.assertRaisesRegex(ValueError, 'completion'):
            managed_pyyaml.consume(fake, {}, object())

    def test_completed_build_is_owner_bound_and_revalidates_actual_output(self):
        cap = self.prepare()
        path, version = managed_pyyaml.location(cap, self.nonce)
        row = {'metadata': {'name': 'PyYAML', 'version': version}, 'download_info': {'url': path.as_uri(),
               'archive_info': {'hashes': {'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}}}}
        self.assertEqual(managed_pyyaml.consume(cap, row, self.nonce)[:2], ('pyyaml', '6.0.3'))
        with self.assertRaisesRegex(ValueError, 'owner'):
            managed_pyyaml.consume(cap, row, object())
        with self.assertRaisesRegex(ValueError, 'completion'):
            managed_pyyaml.consume(managed_pyyaml._Completion(), row, self.nonce)
        path.write_bytes(b'changed after completed probe')
        with self.assertRaisesRegex(ValueError, 'changed'):
            managed_pyyaml.consume(cap, row, self.nonce)
        self.assertNotIn('PYYAML_FORCE_LIBYAML', self.environment)
        self.assertNotIn('PIP_NO_INDEX', self.environment)

    def test_unqualified_build_tool_prevents_any_backend_execution(self):
        self.corrupt_tool = True
        with self.assertRaisesRegex(ValueError, 'integrity'):
            self.prepare()
        self.assertNotIn('build verified PyYAML pure wheel offline', self.commands)
        self.assertFalse((self.root/'.venv').exists())

    def test_failed_build_cannot_issue_completion_or_activate(self):
        self.fail_build = True
        with self.assertRaisesRegex(ValueError, 'build failed'):
            self.prepare()
        self.assertNotIn('probe actual PyYAML pure wheel on managed runtime', self.commands)
        self.assertFalse((self.root/'.venv').exists())

    def test_public_install_failed_build_preserves_user_environment_and_actual_runtime_facts(self):
        from getzilla import managed_environment
        old = self.root/'.venv'
        old.mkdir()
        (old/'user-owned').write_bytes(b'preserve')
        self.fail_build = True

        def run(command, cwd=None, *, env=None):
            self.environment = env
            if command[1:3] == ['-m', 'venv']:
                executable = Path(command[3])/('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
                executable.parent.mkdir(parents=True)
                executable.write_bytes(b'inert owned interpreter')
            if '-c' in command:
                code = command[command.index('-c')+1]
                if 'sysconfig' in code:
                    facts = dict(python_version='3.15.2', version_info=[3, 15, 2], implementation='cpython',
                                 soabi='cpython-315', cache_tag='cpython-315', executable=command[0])
                    return subprocess.CompletedProcess(command, 0, json.dumps(facts), '')
                if 'compatible' in code:
                    return self.checked(command, 'check current PyYAML wheel compatibility')
                if '--without-libyaml' in code:
                    return self.checked(command, 'build verified PyYAML pure wheel offline')
            if '--report' in command:
                return self.checked(command, 'resolve PyYAML binary build-tool closure')
            return subprocess.CompletedProcess(command, 0, '', '')

        with mock.patch.object(subprocess, 'Popen', side_effect=AssertionError('no native process')):
            with self.assertRaises(managed_environment.EnvironmentFailure) as raised:
                managed_environment.install_environment(self.root, '/owned/python', fetch=self.fetch,
                                                        run=run, projects=('bandit',))
        report = managed_environment.failure_details(raised.exception)
        self.assertEqual(report['runtime']['python_version'], '3.15.2')
        self.assertIn('build failed', report['validation_error'])
        self.assertEqual((old/'user-owned').read_bytes(), b'preserve')
        self.assertFalse(old.is_symlink())

    def test_public_resolver_accepts_completed_local_wheel_with_official_rest_of_graph(self):
        from getzilla import managed_environment
        conflict = self.root/'.venv'
        conflict.write_bytes(b'user file prevents activation')
        observed = []

        def run(command, cwd=None, *, env=None):
            self.environment = env
            observed.append(command)
            if command[1:3] == ['-m', 'venv']:
                executable = Path(command[3])/('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
                executable.parent.mkdir(parents=True)
                executable.write_bytes(b'inert owned interpreter')
            if '-c' in command:
                code = command[command.index('-c')+1]
                if 'sysconfig' in code:
                    return subprocess.CompletedProcess(command, 0, json.dumps(dict(python_version='3.15.2',
                        version_info=[3, 15, 2], implementation='cpython', soabi='cpython-315',
                        cache_tag='cpython-315', executable=command[0])), '')
                if 'compatible' in code:
                    return self.checked(command, 'check current PyYAML wheel compatibility')
                if '--without-libyaml' in code:
                    return self.checked(command, 'build verified PyYAML pure wheel offline')
                if 'safe_load' in code:
                    return self.checked(command, 'probe actual PyYAML pure wheel on managed runtime')
                return subprocess.CompletedProcess(command, 0, '{"bandit":"1.9.4","pyyaml":"6.0.3"}', '')
            if '--report' in command:
                report = Path(command[command.index('--report')+1])
                if report.name == 'build-tools.json':
                    return self.checked(command, 'resolve PyYAML binary build-tool closure')
                self.assertIn('PyYAML==6.0.3', command)
                wheel = Path(command[command.index('--find-links')+1])/'pyyaml-6.0.3-py3-none-any.whl'
                rows = [{'metadata': {'name': name, 'version': version}, 'download_info': {'url': url,
                         'archive_info': {'hashes': {'sha256': hashlib.sha256(raw).hexdigest()}}}}
                        for name, version, url, raw in [('PyYAML', '6.0.3', wheel.as_uri(), wheel.read_bytes()),
                          ('bandit', '1.9.4', 'https://files.pythonhosted.org/packages/bandit-1.9.4-py3-none-any.whl',
                           b'inert bandit wheel')]]
                report.write_text(json.dumps({'install': rows}))
            return subprocess.CompletedProcess(command, 0, '', '')

        with mock.patch.object(subprocess, 'Popen', side_effect=AssertionError('no native process')):
            with self.assertRaisesRegex(ValueError, 'user .venv file conflicts'):
                managed_environment.install_environment(self.root, '/owned/python', fetch=self.fetch,
                                                        run=run, projects=('bandit',))
        self.assertTrue(any('--require-hashes' in command and '--no-index' in command for command in observed))
        self.assertEqual(conflict.read_bytes(), b'user file prevents activation')

    def test_backend_guard_refuses_network_process_and_outside_file_without_effects(self):
        actions = ["sys.audit('socket.connect',None)", "sys.audit('subprocess.Popen',None)",
                   'open('+repr(str(self.root.parent/'not-owned-credential'))+')']
        for index, action in enumerate(actions):
            with self.subTest(action=index):
                source = self.root/str(index)/'source'
                package = source/'packaging'
                package.mkdir(parents=True)
                output = source.parent/'wheels'
                output.mkdir()
                body = ("import sys\ndef build_wheel(output,config_settings):\n    try:\n        "+action+
                        "\n    except PermissionError:\n        print('owned guard refused')\n"
                        "    else:\n        raise AssertionError('backend external effect guard missing')\n")
                (package/'_pyyaml_pep517.py').write_text(body)
                result = subprocess.run([sys.executable, '-I', '-B', '-c', managed_pyyaml._BACKEND,
                                         str(source), str(output)], capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), 'owned guard refused')
