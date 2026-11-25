"""Exercise the configured worker and its job executor with local test keys."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from adaptive_trust_ci.policy import CommandSpec
from adaptive_trust_ci.settings import WorkerSettings
from adaptive_trust_ci.signing import Signer
from adaptive_trust_ci.worker import Worker


def main():
    with tempfile.TemporaryDirectory() as directory:
        key = Path(directory) / 'fixture.pem'
        key.write_bytes(Signer.generate().private_key_pem())
        os.environ['TRUST_CI_SIGNING_KEY_PATH'] = str(key)
        worker = Worker.build(WorkerSettings.load())
        policy = worker.catalog.resolve_repository('Dimkox/Getzilla')
        runner = worker.runner_factory(policy, 'Dimkox/Getzilla')
        workspace = worker.settings.workspace_root / 'probe'
        workspace.mkdir()
        subprocess.run(['git', 'init', '-q', str(workspace)], check=True)
        shutil.copyfile('/job-probe.py', workspace / 'probe.py')
        subprocess.run(['git', '-C', str(workspace), 'add', 'probe.py'], check=True)
        subprocess.run(['git', '-C', str(workspace), '-c', 'user.name=Fixture',
                        '-c', 'user.email=fixture@localhost', 'commit', '-qm', 'probe'], check=True)
        gateway = subprocess.check_output(['docker', 'network', 'inspect', 'bridge', '--format',
                                           '{{(index .IPAM.Config 0).Gateway}}'], text=True).strip()
        command = CommandSpec('daemon-isolation', ('python', '/workspace/probe.py', gateway), 60)
        result = runner.executor_factory(policy.sandbox).run(command, workspace, {}, 32768,
                workspace_host_path=worker.settings.workspace_host_root / 'probe')
        print(result.stdout_tail, result.stderr_tail, flush=True)
        if result.exit_code != 0:
            raise RuntimeError(f'worker job failed with exit {result.exit_code}')


if __name__ == '__main__':
    main()
