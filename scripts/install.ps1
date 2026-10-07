# Getzilla installer for Windows (Windows PowerShell 5.1 or PowerShell 7).
#
#   irm https://raw.githubusercontent.com/Dimkox/Getzilla/main/scripts/install.ps1 | iex
#
# Installs what is missing (Git, Python 3.13, Grok Build CLI), downloads Getzilla and
# runs its health check. Uses winget when it is available; otherwise it downloads the
# official installers and installs them for the current user, without administrator
# rights. Nothing is changed in your projects unless you ask for it below.
#
# Optional environment variables (set them before the command above):
#   $env:GETZILLA_HOME = 'D:\Tools\Getzilla'   where Getzilla is kept (default: $HOME\Getzilla)
#   $env:GETZILLA_REF = 'main'                  branch or tag to install
#   $env:GETZILLA_REPO = 'https://...'          Git URL to install from
#   $env:GETZILLA_PROJECT = 'C:\code\my-app'    existing project: print the read-only install plan
#   $env:GETZILLA_NEW_PROJECT = 'C:\code\new'   create a new project there (the folder must not exist)
#   $env:GETZILLA_SKIP_GROK = '1'               do not install the Grok Build CLI
#
# Everything runs inside Install-Getzilla, so a partially downloaded script does nothing,
# and errors are reported without closing your PowerShell window.

function Install-Getzilla {
    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    } catch {
        Write-Verbose 'TLS 1.2 is already the default.'
    }

    $GetzillaHome = $env:GETZILLA_HOME
    if (-not $GetzillaHome) { $GetzillaHome = Join-Path $HOME 'Getzilla' }
    $Ref = $env:GETZILLA_REF
    if (-not $Ref) { $Ref = 'main' }
    $Repo = $env:GETZILLA_REPO
    if (-not $Repo) { $Repo = 'https://github.com/Dimkox/Getzilla.git' }

    Write-Step 'Getzilla installer (Windows)'

    if (-not (Get-Command git -ErrorAction SilentlyContinue)) { Install-Git }
    Write-Step ("Git: " + (& git --version))

    $Python = Find-Python
    if (-not $Python) {
        Install-Python
        $Python = Find-Python
    }
    if (-not $Python) {
        throw 'Python 3.10 or newer is still missing. Open a new PowerShell window and run this installer again.'
    }
    Write-Step ("Python: " + (Invoke-Python $Python @('--version')))

    if ($env:GETZILLA_SKIP_GROK -eq '1') {
        Write-Step 'Skipping the Grok Build CLI (GETZILLA_SKIP_GROK=1).'
    } else {
        Install-Grok
    }

    Get-GetzillaSource -Repo $Repo -Ref $Ref -Destination $GetzillaHome

    Write-Step 'Checking this machine...'
    Push-Location $GetzillaHome
    try {
        Invoke-Python $Python @('scripts/getzilla_doctor.py', '--offer-install')
        $DoctorExit = $LASTEXITCODE
        if ($env:GETZILLA_NEW_PROJECT) {
            Write-Step ("Creating a new project at " + $env:GETZILLA_NEW_PROJECT + " ...")
            Invoke-Python $Python @('scripts/install_into.py', '--materialize-new', $env:GETZILLA_NEW_PROJECT)
            if ($LASTEXITCODE -ne 0) { throw 'Creating the new project failed; see the message above.' }
        } elseif ($env:GETZILLA_PROJECT) {
            Write-Step ("Install plan for " + $env:GETZILLA_PROJECT + " (read-only, nothing is written):")
            Invoke-Python $Python @('scripts/install_into.py', '--plan', $env:GETZILLA_PROJECT)
        }
    } finally {
        Pop-Location
    }

    $PythonText = $Python -join ' '
    Write-Host ''
    if ($DoctorExit -eq 0) {
        Write-Host "Getzilla is ready in $GetzillaHome" -ForegroundColor Green
    } else {
        Write-Host "Getzilla is installed in $GetzillaHome, but the health check reported problems (FAIL lines above)." -ForegroundColor Yellow
    }
    Write-Host ''
    Write-Host 'Next:'
    Write-Host "  1. New project:      cd `"$GetzillaHome`"; $PythonText scripts/install_into.py --materialize-new C:\path\to\new\project"
    Write-Host "     Existing project: cd `"$GetzillaHome`"; $PythonText scripts/install_into.py --plan C:\path\to\your\project"
    Write-Host '  2. In your project run: grok   (first time: sign in, then type /hooks-trust)'
    Write-Host "  3. Vibe-code the feature, then run /getzilla-delivery and $PythonText scripts/getzilla_verify.py --mode pr"
}

function Write-Step([string]$Message) {
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Test-IsWindowsHost {
    return [System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT
}

function Update-SessionPath {
    if (-not (Test-IsWindowsHost)) { return }
    $machine = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $user = [Environment]::GetEnvironmentVariable('Path', 'User')
    $env:Path = (@($machine, $user) | Where-Object { $_ }) -join ';'
}

function Add-UserPath([string]$Directory) {
    $user = [Environment]::GetEnvironmentVariable('Path', 'User')
    $parts = @()
    if ($user) { $parts = $user -split ';' | Where-Object { $_ } }
    if ($parts -notcontains $Directory) {
        [Environment]::SetEnvironmentVariable('Path', (@($parts) + $Directory) -join ';', 'User')
    }
    Update-SessionPath
}

function Test-Winget {
    return [bool](Get-Command winget -ErrorAction SilentlyContinue)
}

function Invoke-Winget([string]$Id, [string[]]$Extra) {
    $arguments = @('install', '-e', '--id', $Id, '--silent', '--accept-package-agreements', '--accept-source-agreements') + $Extra
    & winget @arguments | Out-Host
    return ($LASTEXITCODE -eq 0)
}

function Get-Download([string]$Url, [string]$FileName) {
    $path = Join-Path ([System.IO.Path]::GetTempPath()) $FileName
    Invoke-WebRequest -Uri $Url -OutFile $path -UseBasicParsing
    return $path
}

function Install-Git {
    Write-Step 'Installing Git...'
    if ((Test-Winget) -and (Invoke-Winget 'Git.Git' @())) {
        Update-SessionPath
        if (Get-Command git -ErrorAction SilentlyContinue) { return }
    }
    # No winget (for example in Windows Sandbox): portable MinGit for the current user.
    $release = Invoke-RestMethod -Uri 'https://api.github.com/repos/git-for-windows/git/releases/latest' -UseBasicParsing
    $asset = $release.assets | Where-Object { $_.name -match '^MinGit-[0-9.]+-64-bit\.zip$' } | Select-Object -First 1
    if (-not $asset) { throw 'Could not find a MinGit download. Install Git from https://git-scm.com/downloads and run this installer again.' }
    $zip = Get-Download $asset.browser_download_url $asset.name
    $target = Join-Path $env:LOCALAPPDATA 'Programs\MinGit'
    if (Test-Path $target) { Remove-Item -Recurse -Force $target }
    Expand-Archive -Path $zip -DestinationPath $target -Force
    Remove-Item -Force $zip
    Add-UserPath (Join-Path $target 'cmd')
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) { throw 'Git was installed but is not on PATH. Open a new PowerShell window and run this installer again.' }
}

function Test-PythonCommand([string[]]$Command) {
    try {
        $exe = $Command[0]
        $prefix = @()
        if ($Command.Count -gt 1) { $prefix = $Command[1..($Command.Count - 1)] }
        $probe = 'import sys; print(1 if sys.version_info >= (3, 10) else 0)'
        $result = & $exe @prefix '-c' $probe 2>$null
        return ($LASTEXITCODE -eq 0 -and "$result".Trim() -eq '1')
    } catch {
        return $false
    }
}

function Find-Python {
    foreach ($line in @('py -3', 'python', 'python3')) {
        $candidate = [string[]]($line -split ' ')
        $command = Get-Command $candidate[0] -ErrorAction SilentlyContinue
        if (-not $command) { continue }
        # Skip the Microsoft Store alias that only opens the Store.
        if ($command.Source -and $command.Source -like '*\WindowsApps\*') { continue }
        if (Test-PythonCommand $candidate) { return ,$candidate }
    }
    return $null
}

function Invoke-Python([string[]]$Python, [string[]]$Arguments) {
    $exe = $Python[0]
    $prefix = @()
    if ($Python.Count -gt 1) { $prefix = $Python[1..($Python.Count - 1)] }
    & $exe @prefix @Arguments
}

function Install-Python {
    Write-Step 'Installing Python 3.13...'
    if ((Test-Winget) -and (Invoke-Winget 'Python.Python.3.13' @('--scope', 'user'))) {
        Update-SessionPath
        return
    }
    $installer = Get-Download 'https://www.python.org/ftp/python/3.13.16/python-3.13.16-amd64.exe' 'python-3.13.16-amd64.exe'
    $process = Start-Process -FilePath $installer -Wait -PassThru -ArgumentList @(
        '/quiet', 'InstallAllUsers=0', 'PrependPath=1', 'Include_launcher=1',
        'InstallLauncherAllUsers=0', 'Include_test=0', 'Include_doc=0'
    )
    Remove-Item -Force $installer
    if ($process.ExitCode -ne 0) { throw "The Python installer failed with exit code $($process.ExitCode)." }
    Update-SessionPath
}

function Install-Grok {
    if (Get-Command grok -ErrorAction SilentlyContinue) {
        Write-Step 'Grok Build CLI: already installed.'
        return
    }
    Write-Step 'Installing the Grok Build CLI...'
    # Run the vendor installer in its own process so it cannot end this session.
    $shell = (Get-Process -Id $PID).Path
    & $shell -NoProfile -ExecutionPolicy Bypass -Command 'irm https://x.ai/cli/install.ps1 | iex' |
        ForEach-Object { "$_" -split "`r" } |
        Where-Object { $_.Trim() -and $_ -notmatch '^\s*[#=>\-\s]*\d{1,3}(\.\d+)?\s*%' } |
        Out-Host
    Update-SessionPath
    if (Get-Command grok -ErrorAction SilentlyContinue) {
        Write-Step 'Grok Build CLI installed.'
    } else {
        Write-Step 'Grok Build CLI: if it is not found, open a new PowerShell window. To retry: irm https://x.ai/cli/install.ps1 | iex'
    }
}

function Get-GetzillaSource([string]$Repo, [string]$Ref, [string]$Destination) {
    if (Test-Path (Join-Path $Destination '.git')) {
        Write-Step "Updating Getzilla in $Destination"
        & git -C $Destination fetch --depth 1 origin $Ref
        if ($LASTEXITCODE -ne 0) { throw 'git fetch failed.' }
        & git -C $Destination checkout -q --detach FETCH_HEAD
        if ($LASTEXITCODE -ne 0) { throw 'git checkout failed.' }
    } elseif (Test-Path $Destination) {
        throw "$Destination exists and is not a Getzilla checkout. Set `$env:GETZILLA_HOME to another folder."
    } else {
        Write-Step "Downloading Getzilla to $Destination"
        & git clone -q --depth 1 --branch $Ref $Repo $Destination
        if ($LASTEXITCODE -ne 0) { throw 'git clone failed.' }
    }
}

try {
    Install-Getzilla
} catch {
    Write-Host ("ERROR: " + $_.Exception.Message) -ForegroundColor Red
}
