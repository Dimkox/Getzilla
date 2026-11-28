"""Windows non-admin integration source; no upstream code or host PATH writes.

The real installer/platform run is separate. This fixture checks its native ZIP
staging and a new shell using inert project-owned command files only.
"""
import os
import shutil
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class MachinePreviewLauncherTests(unittest.TestCase):
    def test_platform_launcher_forwards_options_and_status(self):
        scratch = ROOT / '.getzilla/runtime/scratch'
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            home = Path(directory)
            state = home / 'private state'
            state.mkdir()
            marker = state / 'retained'
            marker.write_bytes(b'fixture')
            env = {**os.environ, 'HOME': directory, 'USERPROFILE': directory,
                   'LOCALAPPDATA': str(home / 'Local'), 'GETZILLA_HOME': str(ROOT),
                   'GETZILLA_STATE_HOME': str(state), 'TEMP': directory, 'TMP': directory}
            if os.name == 'nt':
                launcher = ['powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass',
                            '-File', str(ROOT / 'scripts/uninstall.ps1')]
            else:
                launcher = ['/bin/sh', str(ROOT / 'scripts/uninstall.sh')]
            for options, expected in ((['--dry-run'], 0), (['--unknown-option'], 2)):
                with self.subTest(options=options):
                    result = subprocess.run([*launcher, *options], cwd=home, env=env, text=True,
                                            capture_output=True, timeout=30)
                    self.assertEqual(result.returncode, expected, result.stderr)
                    if expected == 0:
                        self.assertIn(str(state), result.stdout)
                        self.assertIn(str(ROOT), result.stdout)
                    self.assertEqual(marker.read_bytes(), b'fixture')


@unittest.skipUnless(os.name == 'nt' and shutil.which('pwsh'), 'Windows non-admin execution pending')
class WindowsNonAdminInstallerTests(unittest.TestCase):
    def test_portable_stage_and_fresh_shell_preserve_user_payload(self):
        scratch = ROOT/'.getzilla/runtime/scratch'
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='owned-nonadmin-installer-', dir=scratch) as owned:
            home = Path(owned)
            library = home/'bootstrap.ps1'
            library.write_text((ROOT/'scripts/install.ps1').read_text().split('\ntry {\n    Install-Getzilla')[0])
            archive = home/'fixture.zip'
            with zipfile.ZipFile(archive, 'w') as bundle:
                bundle.writestr('fixture/qwen.cmd', '@echo off\r\necho 9.0.0\r\n')
                bundle.writestr('fixture/support.dll', 'inert owned DLL')
            harness = home/'join.ps1'
            harness.write_text('''param($Library,$Archive,$Owned)
$ErrorActionPreference='Stop'
. $Library
if (Test-IsElevated) { 'NONADMIN_REQUIRED'; exit 77 }
$env:LOCALAPPDATA=$Owned
$folder=Expand-ToUserPrograms $Archive 'Getzilla\\fixture-current'
if ((Get-Content (Join-Path $folder 'support.dll') -Raw) -cne 'inert owned DLL') { throw 'DLL omitted' }
# Only this child process PATH changes; no User/Machine environment writes.
$env:Path=$folder+';'+$env:Path
$child=Join-Path $Owned 'fresh.ps1'
@'
param($Expected)
$ErrorActionPreference='Stop'
$command=Get-Command qwen -CommandType Application
if ($command.Source -ine (Join-Path $Expected 'qwen.cmd')) { throw 'fresh shell PATH conflict' }
$value=& $command.Source --version
if ($LASTEXITCODE -ne 0 -or "$value".Trim() -cne '9.0.0') { throw 'fresh shell actual version failure' }
'@ | Set-Content $child
& (Get-Process -Id $PID).Path -NoProfile -NonInteractive -File $child $folder
if ($LASTEXITCODE -ne 0) { throw 'fresh shell failed' }
Set-Content -NoNewline (Join-Path $folder 'qwen.cmd') 'user edit'
'owned-nonadmin-stage:PASS'
''')
            result = subprocess.run(['pwsh', '-NoProfile', '-NonInteractive', '-File', str(harness),
                                     str(library), str(archive), str(home)], capture_output=True, text=True, timeout=30)
            if result.returncode == 77:
                self.skipTest('actual process is elevated; non-admin execution remains pending')
            self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
            self.assertIn('owned-nonadmin-stage:PASS', result.stdout)
