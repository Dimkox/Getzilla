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
