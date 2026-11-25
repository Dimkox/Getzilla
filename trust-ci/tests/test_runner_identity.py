import tempfile
import unittest
from pathlib import Path

from adaptive_trust_ci.policy import PolicyError, SandboxSpec
from adaptive_trust_ci.sandbox import ContainerExecutor


class RunnerIdentityTests(unittest.TestCase):
    manifest = 'sha256:' + 'a' * 64
    config = 'sha256:' + 'b' * 64

    def sandbox(self, **updates):
        fields = dict(runtime='docker', image='runner@' + self.manifest,
                      runner_manifest_digest=self.manifest, runner_config_digest=self.config,
                      user='10001', memory_mb=512, cpus=1, pids_limit=64, tmpfs_mb=64)
        return SandboxSpec.from_dict({**fields, **updates})

    def test_executor_uses_verified_config_id_with_pull_never(self):
        spec = self.sandbox()
        self.assertEqual(SandboxSpec.from_dict(spec.to_dict()), spec)
        with tempfile.TemporaryDirectory() as path:
            root = Path(path)
            (root / '.git').mkdir()
            args = ContainerExecutor(spec).build_argv(workspace=root, workspace_host_path=root,
                    command=('true',), env={}, container_name='job')
        self.assertEqual(args[-2:], [self.config, 'true'])
        self.assertEqual(args[args.index('--pull') + 1], 'never')

    def test_unpaired_and_conflicting_digests_refused(self):
        for updates in (dict(image=self.config, runner_manifest_digest=None),
                        dict(runner_manifest_digest=self.config), dict(runner_config_digest='latest'),
                        dict(runner_config_digest=None)):
            with self.subTest(updates=updates), self.assertRaises(PolicyError):
                self.sandbox(**updates)

    def test_implicit_pull_refused(self):
        with self.assertRaises(PolicyError):
            self.sandbox(pull='missing')
