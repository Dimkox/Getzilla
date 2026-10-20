"""trust-ci installs from committed hashed lockfiles that the OSV scan covers (#42)."""
from __future__ import annotations

import re
import sys
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla import known_vulns  # noqa: E402

TRUST_CI = ROOT / 'trust-ci'
REQUIREMENT = re.compile(r'^([a-z0-9][a-z0-9._-]*)==([^\s;\\]+)', re.I)


def locked(name: str) -> dict[str, str]:
    pins: dict[str, str] = {}
    lines = (TRUST_CI / name).read_text(encoding='utf-8').splitlines()
    for index, line in enumerate(lines):
        match = REQUIREMENT.match(line)
        if match:
            following = lines[index + 1] if index + 1 < len(lines) else ''
            assert line.rstrip().endswith('\\') and '--hash=sha256:' in following, f'{name}: {line} has no hash'
            pins[match.group(1).lower().replace('_', '-')] = match.group(2)
    return pins


class TrustCiLockfileTests(unittest.TestCase):
    def test_lockfiles_pin_every_direct_dependency_and_its_transitive_set(self) -> None:
        project = tomllib.loads((TRUST_CI / 'pyproject.toml').read_text(encoding='utf-8'))['project']
        for name, direct in (('requirements.txt', project['dependencies']),
                             ('requirements-test.txt', [*project['dependencies'], *project['optional-dependencies']['test']])):
            pins = locked(name)
            with self.subTest(lockfile=name):
                for requirement in direct:
                    package, version = re.match(r'^([A-Za-z0-9._-]+)(?:\[[^\]]*\])?==(.+)$', requirement).groups()
                    self.assertEqual(pins.get(package.lower()), version, requirement)
                # Transitive dependencies are pinned too, not resolved at install time.
                for transitive in ('starlette', 'pydantic', 'anyio', 'cffi'):
                    self.assertIn(transitive, pins)

    def test_images_install_only_from_the_hashed_lockfile(self) -> None:
        for dockerfile, lockfile in (('Dockerfile.api', 'requirements.txt'), ('Dockerfile.worker', 'requirements.txt'),
                                     ('Dockerfile.test', 'requirements-test.txt'), ('runner.Dockerfile', 'requirements-test.txt')):
            text = (TRUST_CI / dockerfile).read_text(encoding='utf-8')
            with self.subTest(dockerfile=dockerfile):
                self.assertIn(f'--require-hashes -r {lockfile}', text)
                for install in re.findall(r'pip install[^\n]*\s(?:\.|"\.\[test\]")\s*(?:\\|$)', text, re.M):
                    self.assertIn('--no-deps', install)

    def test_the_osv_scan_reads_the_hashed_lockfile(self) -> None:
        pairs = dict(known_vulns._pairs_from_requirements((TRUST_CI / 'requirements.txt').read_text(encoding='utf-8')))
        self.assertEqual({name.lower(): version for name, version in pairs.items()}, locked('requirements.txt'))
        self.assertIsNotNone(known_vulns._manifest_parser('requirements-test.txt'))


if __name__ == '__main__':
    unittest.main()
