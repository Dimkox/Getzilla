"""Trusted tiny held-source composition. It cannot qualify the real research profile."""
from contextlib import contextmanager, chdir
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]


@contextmanager
def research_use_fixture(*, software=True, enabled=True):
    from getzilla import state
    from getzilla.optional_modules import manage_modules
    from tests.execution_contract_support import owned_route
    from tests.test_optional_modules import OptionalModuleTests
    with tempfile.TemporaryDirectory(prefix='research-use-fixture-', dir=ROOT / '.getzilla/runtime') as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        fixture = OptionalModuleTests()
        fixture.install_core(root)
        manage_modules(root, 'install', {'retrieval-research': '0.1.0'}, source=ROOT)
        if enabled:
            manage_modules(root, 'enable', {'context-retrieval': None, 'retrieval-research': None}, source=ROOT)
        config = root / '.getzilla/config'
        config.mkdir(exist_ok=True)
        (config / 'policy.json').write_text('{"schema_version":2,"secret_read_paths":[]}')
        path, composition = populate_research_use(root, software=software)
        (root / '.gitignore').write_text('.getzilla/runtime/\n')
        for argv in (['git', 'init', '-q'], ['git', 'remote', 'add', 'origin', 'https://github.com/Dimkox/Getzilla'],
                     ['git', 'add', '.'], ['git', '-c', 'user.name=fixture', '-c', 'user.email=fixture@example.invalid',
                                         'commit', '-qm', 'trusted inert source fixture']):
            subprocess.run(argv, cwd=root, check=True, capture_output=True)
        with chdir(root), patch.dict(os.environ, {'GETZILLA_SESSION_ID': 'owner'}):
            owned_route(root)
            try:
                yield root, path, composition
            finally:
                state.bind_session(None)


def populate_research_use(root, *, software=True):
    from getzilla.retrieval.research_use_conditions import _Composition
    base = '.getzilla/runtime/use-fixture'
    for directory in ('archives/indices', 'models', 'terms', 'software'):
        (root / base / directory).mkdir(parents=True, mode=0o700)
    grant = (ROOT / 'LICENSE').read_bytes()
    metadata = b'Metadata-Version: 2.4\nName: fixture-package\nVersion: 1.0\nLicense: MIT\nLicense-File: LICENSE\n\n'
    members = {'fixture_package/__init__.py': b'# Never imported.\n',
               'fixture_package-1.0.dist-info/METADATA': metadata,
               'fixture_package-1.0.dist-info/licenses/LICENSE': grant}
    raw = io.BytesIO()
    with zipfile.ZipFile(raw, 'w', zipfile.ZIP_DEFLATED) as archive:
        for name, body in members.items():
            archive.writestr(name, body)
    raw = raw.getvalue()
    def h(body):
        return hashlib.sha256(body).hexdigest()
    filename = 'fixture_package-1.0-py3-none-any.whl'
    url = 'https://files.pythonhosted.org/packages/00/fixture/' + filename
    index = json.dumps({'info': {'name': 'fixture-package', 'version': '1.0'},
                        'urls': [{'filename': filename, 'digests': {'sha256': h(raw)},
                                  'url': url, 'yanked': False, 'packagetype': 'bdist_wheel'}]}).encode()
    (root / base / 'archives' / filename).write_bytes(raw)
    (root / base / 'archives/indices/fixture-package-1.0.json').write_bytes(index)
    for name, body in members.items():
        target = root / base / 'software' / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(body)
        target.chmod(0o400)
    manifest_path = base + '/manifest.json'
    manifest = json.dumps({'codec': {'bytes': 1, 'sha256': h(b'x')},
                           'image': {'config': {'digest': 'sha256:' + h(b'i'), 'size': 1}, 'layers': []}}).encode()
    (root / manifest_path).write_bytes(manifest)
    scope = {'manifest_sha256': h(manifest), 'profile': 'test-only-public-research/v1',
             'abi': 'cpython-312-x86_64-linux-gnu', 'delivery_kind': 'source-use'}
    subject = {'ecosystem': 'PyPI', 'name': 'fixture-package', 'version': '1.0',
               'manifest': manifest_path, 'usage': 'retrieval-research', 'distribution': 'internal',
               'artifact_sha256': h(raw), 'artifact_url': url, 'filename': filename, **scope}
    profile = {'name': subject['name'], 'version': '1.0', 'expression': 'MIT',
               'terms': {'fixture_package-1.0.dist-info/licenses/LICENSE': [h(grant), len(grant)]},
               'notices': {}, 'unchanged': {},
               'metadata': {'fixture_package-1.0.dist-info/METADATA': [h(metadata), len(metadata)]},
               'declared_terms': ['fixture_package-1.0.dist-info/licenses/LICENSE'], 'supplements': {}}
    catalog = {'wheels': [{'name': 'fixture-package', 'version': '1.0', 'filename': filename,
                          'bytes': len(raw), 'sha256': h(raw), 'url': url,
                          'index_filename': 'fixture-package-1.0.json', 'index_bytes': len(index),
                          'index_sha256': h(index), 'index_url': 'https://pypi.org/pypi/fixture-package/1.0/json'}],
               'dependency_exceptions': [{'subject': subject, 'condition_profile': 'test-only'}],
               'retained_source_terms': {}, 'models': {}}
    composition = _Composition(scope['profile'], manifest_path, h(manifest), h(b'tiny catalog'),
                               lambda: catalog, {'test-only': profile},
                               {'project_repository': 'github.com/Dimkox/Getzilla'})
    registration = {'schema_version': 1, 'kind': 'public-research162-use/v1',
                    'artifact_root': base + '/archives', 'model_root': base + '/models',
                    'terms_root': base + '/terms', 'software_root': base + '/software' if software else None}
    path = base + '/registration.json'
    (root / path).write_text(json.dumps(registration))
    (root / path).chmod(0o600)
    (root / '.getzilla/runtime').chmod(0o700)
    for folder in (root / '.getzilla/runtime').rglob('*'):
        if folder.is_dir():
            folder.chmod(0o700)
    return path, composition
