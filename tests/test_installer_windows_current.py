"""PowerShell5.1-compatible resolver fixtures; no real installer or provider runs."""
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which('pwsh'), 'PowerShell interpreter unavailable; Windows evidence pending')
class WindowsCurrentRuntimeTests(unittest.TestCase):
    def test_actual_powershell_node_and_git_resolvers_include_new_major_build(self):
        scratch = ROOT / '.getzilla/runtime/scratch'
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='owned-windows-current-', dir=scratch) as owned:
            home = Path(owned)
            library = home / 'bootstrap.ps1'
            library.write_text((ROOT / 'scripts/install.ps1').read_text().split('\ntry {\n    Install-Getzilla')[0])
            harness = home / 'test.ps1'
            harness.write_text('''param([string]$Library)
$ErrorActionPreference = 'Stop'
$tokens=$null; $errors=$null
[System.Management.Automation.Language.Parser]::ParseFile($Library,[ref]$tokens,[ref]$errors) | Out-Null
if ($errors.Count) { throw ($errors | Out-String) }
. $Library
$script:reads=0
function Invoke-RestMethod {
 param($Uri,[switch]$UseBasicParsing,$TimeoutSec)
 $script:reads++
 if ($Uri -like '*matching-refs*') { return @(@{ref='refs/tags/v4.1.0.windows.2'}) }
 if ($Uri -like '*git-for-windows*') {
  return @{ tag_name='v4.1.0.windows.2';draft=$false;prerelease=$false;assets=@(@{
   name='MinGit-4.1.0-64-bit.zip';digest=('sha256:'+('a'*64));
   browser_download_url='https://github.com/git-for-windows/git/releases/download/v4.1.0.windows.2/MinGit-4.1.0-64-bit.zip'}) }
 }
 return @(@{version='v30.0.0';files=@('win-x64-zip')}, @{version='v31.0.0';files=@('win-x64-zip')}, @{version='v32.0.0rc1';files=@('win-x64-zip')})
}
function Invoke-WebRequest {
 param($Uri,[switch]$UseBasicParsing,$TimeoutSec)
 if ($Uri -cne 'https://nodejs.org/dist/v31.0.0/SHASUMS256.txt') { throw 'not exact new-major checksum URL' }
 return @{Content=(('a'*64)+'  node-v31.0.0-win-x64.zip')}
}
for ($i=0; $i -lt 2; $i++) {
 $script:ResolvedRuntimeTargets=@{}
 $node=Get-CurrentRuntimeTarget 'node-x64'
 if ($node.Version -cne '31.0.0' -or $node.Sha256 -cne ('a'*64)) { throw 'wrong Node target' }
 $git=Get-CurrentRuntimeTarget 'git-x64'
 if ($git.Version -cne '4.1.0.windows.2') { throw 'Git build identity lost' }
}
if ($script:reads -ne 6) { throw 'rerun did not resolve authoritative metadata' }
'owned-current-resolvers:PASS'
''')
            result = subprocess.run(['pwsh', '-NoProfile', '-NonInteractive', '-File', str(harness), str(library)],
                                    capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
            self.assertIn('owned-current-resolvers:PASS', result.stdout)


    def test_installer_failure_rethrows_without_exiting_the_caller(self):
        footer = (ROOT/'scripts/install.ps1').read_text().split('\ntry {\n    Install-Getzilla', 1)[1]
        with tempfile.TemporaryDirectory(prefix='owned-installer-caller-') as directory:
            path = Path(directory)/'footer.ps1'
            path.write_text('try {\n    Install-Getzilla'+footer, encoding='utf-8')
            command = ("$ErrorActionPreference='Stop'; function Install-Getzilla { throw 'owned failure' }; "
                       f"try {{ Invoke-Expression ([IO.File]::ReadAllText('{path}')) }} "
                       "catch { if ($_.Exception.Message -cne 'owned failure') { throw } }; 'owned-caller-alive'")
            result = subprocess.run(['pwsh', '-NoProfile', '-NonInteractive', '-Command', command],
                                    capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertIn('owned-caller-alive', result.stdout)
