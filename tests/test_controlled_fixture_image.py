"""Portable recipe/refusal controls; these do not qualify native/provider execution."""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from getzilla import controlled_fixture as fixture
from getzilla import fenced_fixture


class FixtureImageContractTests(unittest.TestCase):
    def test_root_helper_cannot_run_an_arbitrary_program(self):
        volumes = ['getzilla-fixture-'+'b'*32+'-'+kind for kind in ('state', 'work')]
        with patch.object(fixture, '_command', return_value='c'*64) as command:
            with self.assertRaisesRegex(fixture.FixtureError, 'root_init_unqualified'):
                fenced_fixture._helper('docker', 'sha256:'+'a'*64, volumes, 'print("not initialization")', root=True)
            command.assert_not_called()

    def test_unknown_volume_is_refused_before_container_creation(self):
        with patch.object(fixture, '_command', return_value='c'*64) as command:
            with self.assertRaisesRegex(fixture.FixtureError, 'invalid_volume'):
                fenced_fixture._helper('docker', fixture.IMAGE, ['foreign-state', 'foreign-work'], 'print(1)')
            command.assert_not_called()

    def test_docker_command_uses_the_local_socket_despite_context_environment(self):
        with patch.dict(os.environ, {'DOCKER_HOST': 'tcp://untrusted.invalid:2375', 'DOCKER_CONTEXT': 'untrusted'}), \
                patch.object(fixture.subprocess, 'run') as run:
            self.assertEqual(fixture._command(['/usr/bin/docker', 'version']), '')
            args = run.call_args.args[0]
            self.assertEqual(args[:2], ['/usr/bin/docker', '--config'])
            self.assertEqual(args[3:5], ['--host', 'unix:///var/run/docker.sock'])
            self.assertEqual(run.call_args.kwargs['env'],
                             {'PATH': '/usr/bin:/bin', 'HOME': args[2], 'DOCKER_CONFIG': args[2]})
            self.assertFalse(Path(args[2]).exists())

    def test_contract_names_immutable_official_base_and_exact_inputs(self):
        contract, recipe = fixture._image_contract()
        self.assertEqual(contract['base_reference'], 'python@'+fixture.IMAGE)
        self.assertEqual(contract['codex_sha256'], fixture.CODEX_SHA256)
        self.assertEqual(contract['fixture_sha256'], fixture.FIXTURE_SHA256)
        self.assertEqual(contract['python_version'], '3.12.16')
        self.assertIn(contract['base_reference'], recipe.decode())
        self.assertNotIn(b'RUN ', recipe)

    def test_wrong_binary_refuses_before_docker_allocation(self):
        with tempfile.TemporaryDirectory() as directory:
            bad = Path(directory)/'wrong-codex'
            bad.write_bytes(b'unqualified binary')
            script = Path(__file__).parent/'fixtures/codex_loopback_probe.py'
            with patch.object(fixture, '_command') as command:
                with self.assertRaisesRegex(fixture.FixtureError, 'codex_unqualified'):
                    fixture._immutable_image('docker', script, str(bad))
                command.assert_not_called()

    def test_missing_or_substituted_base_refuses_before_build(self):
        contract, _ = fixture._image_contract()
        for info in ([], [{'Id': 'sha256:'+'f'*64}],
                     [{'Id': fixture.IMAGE, 'RepoDigests': [], 'Os': 'linux', 'Architecture': 'amd64'}]):
            with self.subTest(info=info), patch.object(fixture, '_command', return_value=json.dumps(info)):
                with self.assertRaisesRegex(fixture.FixtureError, 'base_image_unqualified'):
                    fixture._base_image('docker', contract)
        with patch.object(fixture, '_command', side_effect=fixture.FixtureError('container_command_failed')):
            with self.assertRaises(fixture.FixtureError):
                fixture._base_image('docker', contract)

    def test_unknown_built_image_binding_refuses(self):
        owner = 'a'*32
        contract, _ = fixture._image_contract()
        image = 'sha256:'+'b'*64
        labels = {'getzilla.fixture': owner, 'getzilla.fixture.contract': fixture.CONTRACT_SHA256,
                  'getzilla.fixture.base': fixture.IMAGE}
        good = [{'Id': image, 'Os': 'linux', 'Architecture': 'amd64', 'Config': {'Labels': labels}}]
        with patch.object(fixture, '_command', return_value=json.dumps(good)):
            self.assertTrue(fixture._bound_image('docker', image, contract, owner))
        for key, value in (('getzilla.fixture.contract', 'f'*64), ('getzilla.fixture.base', 'sha256:'+'f'*64),
                           ('getzilla.fixture', 'unknown')):
            changed = json.loads(json.dumps(good))
            changed[0]['Config']['Labels'][key] = value
            with self.subTest(key=key), patch.object(fixture, '_command', return_value=json.dumps(changed)):
                with self.assertRaisesRegex(fixture.FixtureError, 'image_mismatch'):
                    fixture._bound_image('docker', image, contract, owner)

    def test_cpu_set_requires_two_available_cpus(self):
        with patch.object(os, 'sched_getaffinity', return_value={20, 21, 22}, create=True):
            with patch.dict(os.environ, {'GETZILLA_FIXTURE_CPUSET': '20,21'}):
                self.assertEqual(fixture._cpu_set(), '20,21')
            for value in ('20', '20,20', '20,23', '20-21', '0,1,2'):
                with self.subTest(value=value), patch.dict(os.environ, {'GETZILLA_FIXTURE_CPUSET': value}):
                    with self.assertRaisesRegex(fixture.FixtureError, 'fixture_cpu_unavailable'):
                        fixture._cpu_set()
