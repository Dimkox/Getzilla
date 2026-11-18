# Getzilla installer for Windows (Windows PowerShell 5.1 or PowerShell 7).
#
#   download this script from a release tag, check its SHA-256 against the digest
#   published in README.md / QUICKSTART.md, then run it (never pipe it into iex)
#
# Resolves current verified Git/Python/PowerShell and selected managed software,
# downloads Getzilla, reports provider setup and runs the final health check.
# Portable runtimes install for the current user without administrator rights. Nothing is changed in your projects unless you ask for it below.
#
# Minimum versions: Windows PowerShell 5.1 can run this installer; Getzilla itself needs
# PowerShell 7.4 or newer (pwsh), which this installer resolves and stages per user,
# Native hook launchers support Windows PowerShell 5.1. Installing pwsh does not
# change the parent shell of an already running client.
#
# Optional environment variables (set them before the command above):
#   $env:GETZILLA_HOME = 'D:\Tools\Getzilla'   where Getzilla is kept (default: $HOME\Getzilla)
#   $env:GETZILLA_REF = 'main'                  branch or tag to install
#   $env:GETZILLA_REPO = 'https://...'          Git URL to install from
#   $env:GETZILLA_PROJECT = 'C:\code\my-app'    existing project: print the read-only install plan
#   $env:GETZILLA_NEW_PROJECT = 'C:\code\new'   create a new project there (the folder must not exist)
#   $env:GETZILLA_AGENT = 'qwen'                qwen | codex | claude | gemini | copilot | grok (default: ask, else qwen)
#   $env:GEMINI_API_KEY / $env:COPILOT_GITHUB_TOKEN  optional keys for Gemini CLI / Copilot CLI
#   $env:GETZILLA_PROVIDER = 'openrouter'       openrouter | native sign-in (default: ask, else openrouter)
#   $env:GETZILLA_MODEL = 'qwen/qwen3-coder'    OpenRouter model id for Qwen Code or Codex
#   $env:OPENROUTER_API_KEY = '...'             your OpenRouter key (otherwise asked for, never echoed)
#   $env:GETZILLA_SKIP_AGENT = '1'              do not install or configure the coding agent
#   $env:GETZILLA_SKIP_GROK = '1'               do not install the Grok Build CLI (when the agent is grok)
#   $env:GETZILLA_EU_AI_ACT = '1' or '0'        turn the optional EU AI Act checks on or off without asking
#   $env:GETZILLA_NONINTERACTIVE = '1'          never ask; use the defaults above
#   $env:GETZILLA_SKIP_WINGET = '1'             do not install winget when it is missing
#
# Every run (first install or re-run) installs the mandatory baseline: the vulnerability data
# (OSV CVE database, current verified OpenGrep) and current release-bound Superpowers, BMAD
# and Spec Kit payloads for your coding agent. There is no option to skip it: if any part does not
# install, the installer stops with an error and says what to fix. Selected managed software
# is freshly resolved each run; the updater also remains available explicitly.
#
# winget is missing on many Windows 10 machines. The installer then installs it
# (App Installer from github.com/microsoft/winget-cli); if that is not possible it
# downloads Git, Python, PowerShell 7 and Node.js directly and installs them for the
# current user, without administrator rights.
#
# Coding agents: Qwen Code and Codex install with npm (Node.js LTS is installed with winget
# when missing), Claude Code and Grok Build with their vendors' official installers. Models
# come from OpenRouter with your own key (https://openrouter.ai/keys) unless you pick the
# agent's own sign-in; the key is stored only in your user settings.
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

    $script:ResolvedRuntimeTargets = @{}

    Install-Git
    Write-Step ("Git: " + (& git --version))

    $Python = @(Install-Python)
    Write-Step ("Python: " + (Invoke-Python $Python @('--version')))

    Install-PowerShell7

    $Agent = Select-Agent
    $Provider = Select-Provider $Agent
    Write-Step "Coding agent: $Agent (models: $Provider)"
    $Compliance = Select-EuAiAct
    if ($Compliance) { Write-Step 'EU AI Act checks: on (getzilla components add compliance:eu-ai-act)' }
    $ComplianceArgs = @()
    if ($Compliance) { $ComplianceArgs = @('--compliance', $Compliance) }
    if ($env:GETZILLA_SKIP_AGENT -eq '1') {
        Write-Step 'Skipping the coding agent (GETZILLA_SKIP_AGENT=1).'
    } else {
        Write-Step "Selected $Agent; exact current software is installed after source setup."
    }

    Get-GetzillaSource -Repo $Repo -Ref $Ref -Destination $GetzillaHome
    # One `getzilla <command>` for every tool (bin\getzilla.cmd), on PATH for new windows.
    Add-UserPath (Join-Path $GetzillaHome 'bin')
    Initialize-PythonEnvironment $Python $GetzillaHome
    $Python = @((Join-Path $GetzillaHome '.venv\Scripts\python.exe'))
    Add-UserPath (Join-Path $GetzillaHome '.venv\Scripts')
    Install-Agent $Agent $Python $GetzillaHome
    $AgentExit = 0

    Push-Location $GetzillaHome
    try {
        if ($env:GETZILLA_SKIP_AGENT -ne '1') {
            Set-AgentConfiguration $Python $Agent $Provider
            $AgentExit = $LASTEXITCODE
        }
    } finally {
        Pop-Location
    }

    Update-SecurityData $Python $GetzillaHome
    Install-WorkflowBaseline $Python $GetzillaHome

    Push-Location $GetzillaHome
    try {
        if ($env:GETZILLA_NEW_PROJECT) {
            Write-Step ("Creating a new project at " + $env:GETZILLA_NEW_PROJECT + " ...")
            Invoke-Python $Python (@('scripts/install_into.py', '--materialize-new', $env:GETZILLA_NEW_PROJECT, '--agents', $Agent) + $ComplianceArgs)
            if ($LASTEXITCODE -ne 0) { throw 'Creating the new project failed; see the message above.' }
            Write-Step 'Connecting the baseline (Superpowers, BMAD, Spec Kit) to the new project...'
            Invoke-Python $Python @('scripts/getzilla_baseline.py', 'apply', '--project', $env:GETZILLA_NEW_PROJECT, '--agent', $Agent)
            if ($LASTEXITCODE -ne 0) {
                throw ('The baseline was not connected to ' + $env:GETZILLA_NEW_PROJECT + ' (FAIL lines above). Fix it and run: cd "' +
                    $GetzillaHome + '"; ' + ($Python -join ' ') + ' scripts/getzilla_baseline.py apply --project "' +
                    $env:GETZILLA_NEW_PROJECT + '" --agent ' + $Agent)
            }
        } elseif ($env:GETZILLA_PROJECT) {
            Write-Step ("Install plan for " + $env:GETZILLA_PROJECT + " (read-only, nothing is written):")
            Invoke-Python $Python (@('scripts/install_into.py', '--plan', $env:GETZILLA_PROJECT) + $ComplianceArgs)
            if ($Compliance) {
                Write-Step ('To turn on EU AI Act checks there: cd "' + $env:GETZILLA_PROJECT + '"; getzilla components add compliance:eu-ai-act')
            }
        }
    } finally {
        Pop-Location
    }

    $PythonText = $Python -join ' '
    Push-Location $GetzillaHome
    try {
        Write-Step 'Checking this machine after all updates...'
        $final = @('scripts/getzilla_install_managed.py', '--verify-only', '--home', $GetzillaHome)
        if ($env:GETZILLA_SKIP_AGENT -ne '1') { $final += @('--agent', $Agent) }
        foreach ($tool in @($env:GETZILLA_TOOLS -split ',' | Where-Object { $_ })) { $final += @('--tool', $tool.Trim()) }
        Invoke-Python $Python $final
        if ($LASTEXITCODE -ne 0) { throw 'Actual managed software/PATH changed or latest metadata is unavailable.' }
        Invoke-Python $Python @('scripts/getzilla_doctor.py', '--offer-install')
        $DoctorExit = $LASTEXITCODE
    } finally { Pop-Location }
    Write-Host ''
    if ($DoctorExit -eq 0 -and $AgentExit -eq 0) {
        Write-Host "Getzilla is ready in $GetzillaHome" -ForegroundColor Green
    } else {
        throw "Getzilla installation is incomplete: health=$DoctorExit, agent/provider=$AgentExit. Follow the errors and next steps above."
    }
    Write-Host ''
    Write-Host 'Next:'
    Write-Host '  0. Every Getzilla tool is one command: getzilla help   (open a new PowerShell window first)'
    Write-Host "  1. New project:      cd `"$GetzillaHome`"; $PythonText scripts/install_into.py --materialize-new C:\path\to\new\project"
    Write-Host "     Existing project: cd `"$GetzillaHome`"; $PythonText scripts/install_into.py --plan C:\path\to\your\project"
    Write-Host ('  2. In your project run: ' + (Get-AgentCommand $Agent))
    Write-Host "  3. Vibe-code the feature, then run /getzilla-delivery and $PythonText scripts/getzilla_verify.py --mode pr"
}

function Write-Step([string]$Message) {
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Get-InstallLogDir {
    # Third-party installer logs, so a failed or stuck step can be diagnosed afterwards.
    $dir = $env:GETZILLA_LOG_DIR
    if (-not $dir) { $dir = Join-Path $env:LOCALAPPDATA 'Getzilla\logs' }
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    return $dir
}

function Test-IsWindowsHost {
    return [System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT
}

function Update-SessionPath {
    if (-not (Test-IsWindowsHost)) { return }
    $machine = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $user = [Environment]::GetEnvironmentVariable('Path', 'User')
    $env:Path = (@($env:Path, $user, $machine) | Where-Object { $_ }) -join ';'
}

function Add-UserPath([string]$Directory) {
    $user = [Environment]::GetEnvironmentVariable('Path', 'User')
    $parts = @()
    if ($user) { $parts = $user -split ';' | Where-Object { $_ } }
    $parts = @($parts | Where-Object { $_ -ine $Directory })
    [Environment]::SetEnvironmentVariable('Path', (@($Directory) + $parts) -join ';', 'User')
    $env:Path = $Directory + ';' + $env:Path
    Update-SessionPath
}

function Test-Winget {
    return [bool](Get-Command winget -ErrorAction SilentlyContinue)
}

function Test-IsElevated {
    if (-not (Test-IsWindowsHost)) { return $false }
    try {
        $principal = New-Object Security.Principal.WindowsPrincipal ([Security.Principal.WindowsIdentity]::GetCurrent())
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

function Test-WingetInstalls {
    # winget installs Git, PowerShell 7 and Node.js machine-wide and Python's launcher for all users.
    # Without an elevated session each of those waits on a UAC prompt, which hangs unattended runs
    # (Windows Sandbox, CI, remote shells); the pinned per-user downloads need no administrator.
    return ((Test-Winget) -and (Test-IsElevated))
}

function Invoke-Winget([string]$Id, [string[]]$Extra) {
    # The winget community source only: the msstore source fails in some regions (0x8a15003b) and,
    # matching the same id, makes winget refuse to choose a package at all.
    $logDir = Get-InstallLogDir
    $installerLog = Join-Path $logDir "winget-$Id.log"
    # --verbose-logs: winget's own diagnostic log; --log: the package installer's log (MSI, Inno, ...).
    $arguments = @('install', '-e', '--id', $Id, '--source', 'winget', '--silent', '--accept-package-agreements',
        '--accept-source-agreements', '--verbose-logs', '--log', $installerLog) + $Extra
    Write-Step "winget logs: $installerLog and $logDir\winget-diag"
    # winget writes UTF-8; Windows PowerShell decodes piped native output with the OEM code page,
    # which turns localized (for example Russian) messages into mojibake.
    $previousEncoding = [Console]::OutputEncoding
    try {
        [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
        & winget @arguments | Out-Host
        $exitCode = $LASTEXITCODE
    } finally {
        [Console]::OutputEncoding = $previousEncoding
        $diag = Join-Path $env:LOCALAPPDATA 'Packages\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\LocalState\DiagOutputDir'
        if (Test-Path $diag) {
            $target = Join-Path $logDir 'winget-diag'
            New-Item -ItemType Directory -Force -Path $target | Out-Null
            Get-ChildItem -Path $diag -Filter '*.log' | Sort-Object LastWriteTime | Select-Object -Last 3 |
                Copy-Item -Destination $target -Force -ErrorAction SilentlyContinue
        }
    }
    return ($exitCode -eq 0)
}

function Get-WindowsArchitecture {
    $name = $env:PROCESSOR_ARCHITEW6432
    if (-not $name) { $name = $env:PROCESSOR_ARCHITECTURE }
    switch -Regex ("$name") {
        '^ARM64$' { return 'arm64' }
        '^x86$' { return 'x86' }
        default { return 'x64' }
    }
}

function Select-WingetDependencies([string]$Root, [string]$Architecture) {
    if (-not (Test-Path $Root)) { return @() }
    return @(Get-ChildItem -Path $Root -Recurse -File -Include '*.appx', '*.msix' |
        Where-Object { $_.Directory.Name -eq $Architecture -or $_.Name -match "_$([regex]::Escape($Architecture))\." } |
        ForEach-Object { $_.FullName })
}

function Initialize-Winget {
    $perUser = 'Not running as administrator: tools are installed for the current user from pinned, verified downloads (no UAC prompts).'
    if (Test-Winget) {
        Write-Step ('winget: ' + ((& winget --version) | Select-Object -First 1))
        if (-not (Test-IsElevated)) { Write-Step $perUser }
        return
    }
    if ($env:GETZILLA_SKIP_WINGET -eq '1') {
        Write-Step 'winget is missing; skipping its installation (GETZILLA_SKIP_WINGET=1). Using direct downloads.'
        return
    }
    if (-not (Test-IsElevated)) {
        Write-Step $perUser
        return
    }
    try {
        if (Install-Winget) {
            Write-Step ('winget installed: ' + ((& winget --version) | Select-Object -First 1))
            return
        }
    } catch {
        Write-Verbose $_.Exception.Message
    }
    Write-Step 'winget could not be installed here; Git, Python, PowerShell 7 and Node.js will be downloaded directly.'
}

function Install-Winget {
    if ($PSVersionTable.PSVersion.Major -ge 7) {
        Import-Module Appx -UseWindowsPowerShell -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    }
    if (-not (Get-Command Add-AppxPackage -ErrorAction SilentlyContinue)) { return $false }
    Write-Step 'winget is missing (common on Windows 10). Installing App Installer from github.com/microsoft/winget-cli...'
    $zip = Get-PinnedDownload 'winget-dependencies'
    $folder = Join-Path ([System.IO.Path]::GetTempPath()) 'getzilla-winget-dependencies'
    if (Test-Path $folder) { Remove-Item -Recurse -Force $folder }
    Expand-Archive -Path $zip -DestinationPath $folder -Force
    Remove-Item -Force $zip
    $paths = @(Select-WingetDependencies $folder (Get-WindowsArchitecture))
    $package = Get-PinnedDownload 'winget'
    if ($paths.Count) {
        Add-AppxPackage -Path $package -DependencyPath $paths -ErrorAction Stop -Verbose
    } else {
        Add-AppxPackage -Path $package -ErrorAction Stop -Verbose
    }
    Remove-Item -Force $package
    $apps = Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps'
    if (($env:Path -split ';') -notcontains $apps) { $env:Path = "$env:Path;$apps" }
    return (Test-Winget)
}

function Expand-ToUserPrograms([string]$Zip, [string]$Name) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $target = Join-Path $env:LOCALAPPDATA "Programs\$Name"
    $staging = Join-Path $env:LOCALAPPDATA ("Programs\Getzilla\.staging-" + [guid]::NewGuid().ToString('N'))
    $archive = [IO.Compression.ZipFile]::OpenRead($Zip)
    try {
        if ($archive.Entries.Count -gt 16384) { throw 'Runtime ZIP member count exceeds bound.' }
        $total = 0L; $files = @{}
        foreach ($entry in $archive.Entries) {
            $nameInZip = $entry.FullName.Replace('\','/')
            if ($nameInZip -match '(^/|:|(^|/)\.\.?(/|$))' -or ($entry.ExternalAttributes -shr 16 -band 61440) -eq 40960) { throw 'Unsafe runtime ZIP member.' }
            $total += $entry.Length
            if ($total -gt 536870912 -or $entry.Length -gt 134217728) { throw 'Runtime ZIP byte bound exceeded.' }
            if (-not $entry.Name) { continue }
            if ($files.ContainsKey($nameInZip)) { throw 'Duplicate runtime ZIP member.' }
            $files[$nameInZip] = $entry
        }
        $prefix = ''
        $roots = @($files.Keys | ForEach-Object { ($_ -split '/')[0] } | Select-Object -Unique)
        if ($roots.Count -eq 1 -and @($files.Keys | Where-Object { $_ -notmatch '/' }).Count -eq 0) { $prefix = $roots[0] + '/' }
        $existing = Test-Path -LiteralPath $target
        if (-not $existing) { New-Item -ItemType Directory -Path $staging -Force | Out-Null }
        foreach ($key in $files.Keys) {
            $relative = $key.Substring($prefix.Length)
            $destination = Join-Path $(if ($existing) { $target } else { $staging }) $relative
            $stream = $files[$key].Open()
            try {
                if ($existing) {
                    if (-not (Test-Path -LiteralPath $destination -PathType Leaf) -or (Get-Item -LiteralPath $destination).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Runtime/user conflict: $destination" }
                    $sha = [Security.Cryptography.SHA256]::Create()
                    try { $expected = ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-','').ToLowerInvariant() } finally { $sha.Dispose() }
                    if ((Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant() -cne $expected) { throw "Runtime/user byte conflict: $destination" }
                } else {
                    New-Item -ItemType Directory -Force -Path (Split-Path $destination) | Out-Null
                    $output = [IO.File]::Create($destination)
                    try { $stream.CopyTo($output) } finally { $output.Dispose() }
                }
            } finally { $stream.Dispose() }
        }
        if (-not $existing) {
            New-Item -ItemType Directory -Force -Path (Split-Path $target) | Out-Null
            Move-Item -LiteralPath $staging -Destination $target
        }
    } finally {
        $archive.Dispose()
        Remove-Item -LiteralPath $Zip -Force
        if (Test-Path -LiteralPath $staging) { Remove-Item -LiteralPath $staging -Recurse -Force }
    }
    return $target
}

function Get-Download([string]$Url, [string]$FileName) {
    if ($FileName -match '[/\\:]' -or $FileName -in @('.', '..')) { throw 'Unsafe download filename.' }
    $directory = Join-Path $env:LOCALAPPDATA ('Getzilla\downloads\' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
    $path = Join-Path $directory $FileName
    Invoke-WebRequest -Uri $Url -OutFile $path -UseBasicParsing -TimeoutSec 120
    return $path
}

# Direct downloads used only when winget cannot install a tool (for example in Windows Sandbox).
# Exact releases with their published SHA-256: no GitHub API rate limit, no unreviewed "latest".
$PinnedDownloads = @{
    'winget'              = @{ Url = 'https://github.com/microsoft/winget-cli/releases/download/v1.29.380/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle'; Sha256 = '65dea9c01ce08ee7b763366b27c0e651f97db857c11ca9b9c301826c10092f2e' }
    'winget-dependencies' = @{ Url = 'https://github.com/microsoft/winget-cli/releases/download/v1.29.380/DesktopAppInstaller_Dependencies.zip'; Sha256 = 'ba875afe9d190f61218985ac0292a99d1db710bf93e13c68944ca9d89f0d82d1' }
    'git-x64'             = @{ Url = 'https://github.com/git-for-windows/git/releases/download/v2.56.0.windows.2/MinGit-2.56.0.2-64-bit.zip'; Sha256 = 'da35e72aa21c005a5a0d298cfbae110bc1609a815730ea0dde84b01a1b3cd3be' }
    'git-arm64'           = @{ Url = 'https://github.com/git-for-windows/git/releases/download/v2.56.0.windows.2/MinGit-2.56.0.2-arm64.zip'; Sha256 = '38b33dc6024026e3315cf88ab2cfea65205bbd7bb3a8e824bd21c8ad4fe609a7' }
    'python-x64'          = @{ Url = 'https://www.python.org/ftp/python/3.13.16/python-3.13.16-amd64.exe'; Sha256 = 'fb4f9f5d438b2396da0086dc70b935c530cb578e37adc6d354f7ad2037fee83b' }
    'python-arm64'        = @{ Url = 'https://www.python.org/ftp/python/3.13.16/python-3.13.16-arm64.exe'; Sha256 = '696e2226062c6ec3622c13f143d28336a856968518e49cb4f4c62513215a4f5d' }
    'pwsh-x64'            = @{ Url = 'https://github.com/PowerShell/PowerShell/releases/download/v7.6.7/PowerShell-7.6.7-win-x64.zip'; Sha256 = 'd2f952ebdbf24386cb8923553aa58e41a846db35a6155ea04c58142a4b16dbb7' }
    'pwsh-arm64'          = @{ Url = 'https://github.com/PowerShell/PowerShell/releases/download/v7.6.7/PowerShell-7.6.7-win-arm64.zip'; Sha256 = '119bd9221254ef3637523cb1990797618f5fd68848b57de40f12b561d743149e' }
    'node-x64'            = @{ Url = 'https://nodejs.org/dist/v24.20.0/node-v24.20.0-win-x64.zip'; Sha256 = '6cac9ffbca8f6a47091e4b5c772e0606049c3871cb67d900c0cedde630e545ba' }
    'node-arm64'          = @{ Url = 'https://nodejs.org/dist/v24.20.0/node-v24.20.0-win-arm64.zip'; Sha256 = '31c6799744de8a54601643098040c68c3697e56c94e407d61d0e5fa5f34191d7' }
}

function Get-PinnedDownload([string]$Key) {
    $pin = if ($Key -match '^(git|python|pwsh|node)-') { Get-CurrentRuntimeTarget $Key } else { $PinnedDownloads[$Key] }
    if (-not $pin) { throw "No pinned download for '$Key' on this machine. Install it manually and run this installer again." }
    $name = Split-Path $pin.Url -Leaf
    $path = Get-Download $pin.Url $name
    $actual = (Get-FileHash -Path $path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $pin.Sha256) {
        Remove-Item -Force $path
        throw "SHA-256 mismatch for $name (expected $($pin.Sha256), got $actual); the download was deleted."
    }
    return $path
}

function Install-Git { Install-CurrentRuntime 'git' | Out-Null }

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

function Install-Python { return (Install-CurrentRuntime 'python') }

$MinimumPowerShell = [version]'7.4'

function Get-Pwsh {
    $command = Get-Command pwsh -ErrorAction SilentlyContinue
    if (-not $command) { return $null }
    try {
        $text = (& $command.Source -NoProfile -Command '$PSVersionTable.PSVersion.ToString()' 2>$null | Select-Object -First 1)
        if ($LASTEXITCODE -ne 0 -or "$text".Trim() -notmatch '^\d+\.\d+\.\d+$') { return $null }
        $version = [version](("$text".Trim()) -replace '[^0-9.].*$', '')
    } catch {
        return $null
    }
    return [pscustomobject]@{ Path = $command.Source; Version = $version }
}

function Install-PowerShell7 { Install-CurrentRuntime 'pwsh' | Out-Null }

function Initialize-PythonEnvironment([string[]]$Python, [string]$GetzillaHome) {
    Write-Step "Resolving current test/quality tools and verifying their complete wheel closure..."
    Invoke-Python $Python @((Join-Path $GetzillaHome 'scripts/getzilla_install_managed.py'), '--environment-only', '--home', $GetzillaHome)
    if ($LASTEXITCODE -ne 0) { throw 'Current managed Python environment is incomplete; no historical pins were used.' }
}

function Update-SecurityData([string[]]$Python, [string]$GetzillaHome) {
    # Not optional: without vulnerability data the gates would scan against an empty CVE
    # database, so a failure stops the install instead of warning.
    Write-Step 'Updating vulnerability data (OSV CVE database) and current verified OpenGrep...'
    Push-Location $GetzillaHome
    try {
        Invoke-Python $Python @('scripts/getzilla_update.py', '--only', 'osv', '--only', 'opengrep')
        if ($LASTEXITCODE -ne 0) {
            throw ('Vulnerability data did not install (FAIL lines above). Fix the network or the error and run this installer again (or: cd "' +
                $GetzillaHome + '"; ' + ($Python -join ' ') + ' scripts/getzilla_update.py --only osv --only opengrep).')
        }
    } finally {
        Pop-Location
    }
}

function Install-WorkflowBaseline([string[]]$Python, [string]$GetzillaHome) {
    # Not optional: Superpowers, BMAD and Spec Kit at the pinned, commit-verified versions.
    # BMAD runs on Node.js; Spec Kit installs through uv, which brings its own Python 3.11+.
    if (-not (Test-Node 20)) { throw 'The verified current Node runtime is unavailable/incompatible.' }
    $venvPython = Join-Path $GetzillaHome '.venv\Scripts\python.exe'
    if (-not (Test-Path -LiteralPath $venvPython)) {
        throw "Getzilla's Python environment ($GetzillaHome\.venv) is missing; it is needed by the workflow source/data adapter."
    }
    Write-Step 'Resolving the current verified workflow baseline (Superpowers, BMAD, Spec Kit)...'
    $previousPath = $env:Path
    $env:Path = (Join-Path $GetzillaHome '.venv\Scripts') + ';' + $env:Path
    Push-Location $GetzillaHome
    try {
        Invoke-Python $Python @('scripts/getzilla_update.py', '--only', 'baseline')
        if ($LASTEXITCODE -ne 0) {
            throw ('The workflow baseline did not install (FAIL lines above). Fix it and run this installer again (or: cd "' +
                $GetzillaHome + '"; ' + ($Python -join ' ') + ' scripts/getzilla_update.py --only baseline).')
        }
    } finally {
        Pop-Location
        $env:Path = $previousPath
    }
}

function Test-CanAsk {
    if ($env:GETZILLA_NONINTERACTIVE -eq '1') { return $false }
    try {
        return ([Environment]::UserInteractive -and -not [Console]::IsInputRedirected)
    } catch {
        return $false
    }
}

function Read-Choice([string]$Prompt, [string]$Default) {
    if (-not (Test-CanAsk)) { return $Default }
    try {
        $answer = Read-Host $Prompt
    } catch {
        return $Default
    }
    if ($answer) { return $answer.Trim() }
    return $Default
}

# Offline hints only: the Windows time zone or the region of an EU member state. Nothing is looked
# up on the network and the IP address is never used.
function Test-EuHint {
    $zones = @('W. Europe Standard Time', 'Central Europe Standard Time', 'Central European Standard Time',
        'Romance Standard Time', 'GTB Standard Time', 'FLE Standard Time', 'E. Europe Standard Time',
        'GMT Standard Time')
    $regions = @('AT', 'BE', 'BG', 'HR', 'CY', 'CZ', 'DK', 'EE', 'FI', 'FR', 'DE', 'GR', 'HU', 'IE', 'IT',
        'LV', 'LT', 'LU', 'MT', 'NL', 'PL', 'PT', 'RO', 'SK', 'SI', 'ES', 'SE')
    try {
        if ([System.TimeZoneInfo]::Local.Id -in $zones) { return $true }
        if ([System.Globalization.RegionInfo]::CurrentRegion.TwoLetterISORegionName -in $regions) { return $true }
    } catch {
        return $false
    }
    return $false
}

# Returns 'eu-ai-act' when the optional checks are turned on, an empty string otherwise. Default: off.
function Select-EuAiAct {
    switch ("$env:GETZILLA_EU_AI_ACT".ToLowerInvariant()) {
        { $_ -in @('1', 'yes', 'true', 'on') } { return 'eu-ai-act' }
        { $_ -in @('0', 'no', 'false', 'off') } { return '' }
    }
    if (-not (Test-EuHint)) { return '' }
    $answer = Read-Choice 'Does your project have users in the EU? Turn on EU AI Act checks (optional, can be added later) [y/N]' 'n'
    if ($answer -in @('y', 'Y', 'yes', 'Yes', 'YES')) { return 'eu-ai-act' }
    return ''
}

function Select-Agent {
    $agent = $env:GETZILLA_AGENT
    if (-not $agent) {
        switch (Read-Choice 'Coding agent: 1) Qwen Code  2) Codex  3) Claude Code  4) Gemini CLI  5) Copilot CLI  6) Grok Build  [1]' '1') {
            { $_ -in @('2', 'codex') } { $agent = 'codex'; break }
            { $_ -in @('3', 'claude') } { $agent = 'claude'; break }
            { $_ -in @('4', 'gemini') } { $agent = 'gemini'; break }
            { $_ -in @('5', 'copilot') } { $agent = 'copilot'; break }
            { $_ -in @('6', 'grok') } { $agent = 'grok'; break }
            default { $agent = 'qwen' }
        }
    }
    if ($agent -notin @('qwen', 'codex', 'claude', 'gemini', 'copilot', 'grok')) {
        throw "GETZILLA_AGENT must be qwen, codex, claude, gemini, copilot or grok (got '$agent')."
    }
    return $agent
}

function Select-Provider([string]$Agent) {
    if ($Agent -in @('grok', 'gemini', 'copilot')) { return 'native' }
    $provider = $env:GETZILLA_PROVIDER
    if (-not $provider) {
        switch (Read-Choice "Models: 1) OpenRouter with your own key  2) the agent's own sign-in  [1]" '1') {
            { $_ -in @('2', 'native') } { $provider = 'native'; break }
            default { $provider = 'openrouter' }
        }
    }
    if ($provider -notin @('openrouter', 'native')) {
        throw "GETZILLA_PROVIDER must be openrouter or native (got '$provider')."
    }
    return $provider
}

function Get-AgentCommand([string]$Agent) {
    switch ($Agent) {
        'codex' { return 'codex   (trust the project when asked)' }
        'claude' { return 'claude   (trust the project folder when asked)' }
        'gemini' { return 'gemini   (trust the folder when asked)' }
        'copilot' { return 'copilot   (first time: /login, and trust the folder)' }
        'grok' { return 'grok   (first time: sign in, then type /hooks-trust)' }
        default { return 'qwen' }
    }
}

function Install-Agent([string]$Agent, [string[]]$Python, [string]$GetzillaHome) {
    $arguments = @((Join-Path $GetzillaHome 'scripts/getzilla_install_managed.py'), '--home', $GetzillaHome)
    if ($env:GETZILLA_SKIP_AGENT -ne '1') { $arguments += @('--agent', $Agent) }
    foreach ($tool in @($env:GETZILLA_TOOLS -split ',' | Where-Object { $_ })) { $arguments += @('--tool', $tool.Trim()) }
    Invoke-Python $Python $arguments
    if ($LASTEXITCODE -ne 0) { throw 'Current selected managed software is incomplete; see exact target/path/error above.' }
    $state = if ($env:GETZILLA_STATE_HOME) { $env:GETZILLA_STATE_HOME } else { Join-Path $HOME '.getzilla' }
    Add-UserPath (Join-Path $state 'bin')
}

function Test-Node([int]$Minimum = 20) {
    if (-not (Get-Command node -ErrorAction SilentlyContinue)) { return $false }
    try {
        # `node --version` prints vMAJOR.MINOR.PATCH. No inline program: Windows PowerShell 5.1
        # strips the double quotes inside native arguments, and with ErrorActionPreference Stop
        # any stderr line from such a broken call would abort the whole installer.
        $text = (& node --version 2>$null | Select-Object -First 1)
        if ($LASTEXITCODE -ne 0 -or "$text".Trim() -notmatch '^v\d+\.\d+\.\d+$') { return $false }
        return ([int](("$text".Trim()) -replace '^v(\d+).*$', '$1') -ge $Minimum)
    } catch {
        return $false
    }
}

function Install-Node([int]$Minimum = 20) {
    Install-CurrentRuntime 'node' | Out-Null
    if (-not (Test-Node $Minimum)) { throw 'Latest stable Node is incompatible with the selected component minimum.' }
    return $true
}



function Set-AgentConfiguration([string[]]$Python, [string]$Agent, [string]$Provider) {
    $arguments = @('scripts/getzilla_setup_agent.py', '--agent', $Agent, '--provider', $Provider)
    if ($env:GETZILLA_MODEL) { $arguments += @('--model', $env:GETZILLA_MODEL) }
    $keyName = $null
    $prompt = $null
    switch ($Agent) {
        'gemini' { $keyName = 'GEMINI_API_KEY'; $prompt = 'Gemini API key (optional, Enter to sign in with Google instead)' }
        'copilot' { $keyName = 'COPILOT_GITHUB_TOKEN'; $prompt = 'GitHub token for Copilot (optional, Enter to use /login instead)' }
        'grok' { }
        default {
            if ($Provider -eq 'openrouter') {
                $keyName = 'OPENROUTER_API_KEY'
                $prompt = 'OpenRouter API key (create one at https://openrouter.ai/keys, Enter to skip)'
            }
        }
    }
    $key = $null
    if ($keyName) { $key = [Environment]::GetEnvironmentVariable($keyName) }
    if ($keyName -and -not $key -and (Test-CanAsk)) {
        try {
            $secure = Read-Host $prompt -AsSecureString
            $key = [System.Net.NetworkCredential]::new('', $secure).Password
        } catch {
            $key = $null
        }
    }
    Write-Step "Configuring $Agent..."
    $exe = $Python[0]
    $prefix = @()
    if ($Python.Count -gt 1) { $prefix = $Python[1..($Python.Count - 1)] }
    if ($key) {
        $key | & $exe @prefix @arguments '--key-stdin'
    } else {
        $names = @('OPENROUTER_API_KEY', 'GEMINI_API_KEY', 'COPILOT_GITHUB_TOKEN')
        $saved = @{}
        foreach ($name in $names) {
            $saved[$name] = [Environment]::GetEnvironmentVariable($name)
            [Environment]::SetEnvironmentVariable($name, $null)
        }
        try {
            $null | & $exe @prefix @arguments
        } finally {
            foreach ($name in $names) { [Environment]::SetEnvironmentVariable($name, $saved[$name]) }
        }
    }
    if ($LASTEXITCODE -ne 0) {
        Write-Step 'Agent configuration failed (see the message above); run scripts/getzilla_setup_agent.py again later.'
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

function Get-CurrentGithubRelease([string]$Repository, [switch]$WindowsGit) {
    $base = 'https://api.github.com/repos/' + $Repository
    $release = Invoke-RestMethod -Uri "$base/releases/latest" -UseBasicParsing -TimeoutSec 20
    $pattern = if ($WindowsGit) { '^v(\d+\.\d+\.\d+)\.windows\.(\d+)$' } else { '^v(\d+\.\d+\.\d+)$' }
    if ($release.draft -or $release.prerelease -or $release.tag_name -notmatch $pattern) { throw 'Official current release identity is invalid.' }
    $current = if ($WindowsGit) { [version]($Matches[1] + '.' + $Matches[2]) } else { [version]$Matches[1] }
    $refs = @(Invoke-RestMethod -Uri "$base/git/matching-refs/tags/" -UseBasicParsing -TimeoutSec 20)
    if (-not $refs.Count -or $refs.Count -gt 4096) { throw 'Complete official tag index is unavailable or exceeds bounds.' }
    $seen = @{}; $higher = @()
    foreach ($row in $refs) {
        if (-not $row.ref.StartsWith('refs/tags/') -or $seen.ContainsKey($row.ref)) { throw 'Invalid or duplicate official tag.' }
        $seen[$row.ref] = $true
        $tag = $row.ref.Substring(10)
        if ($tag -match $pattern) {
            $version = if ($WindowsGit) { [version]($Matches[1] + '.' + $Matches[2]) } else { [version]$Matches[1] }
            if ($version -gt $current) { $higher += @{ Tag=$tag; Version=$version } }
        }
    }
    if ($higher.Count -gt 16) { throw 'Higher stable release lookup exceeds bounds.' }
    foreach ($candidate in @($higher | Sort-Object { $_.Version } -Descending)) {
        try { $item = Invoke-RestMethod -Uri "$base/releases/tags/$($candidate.Tag)" -UseBasicParsing -TimeoutSec 20 }
        catch {
            if ($_.Exception.Response -and [int]$_.Exception.Response.StatusCode -eq 404) { continue }
            throw
        }
        if ($item.tag_name -cne $candidate.Tag) { throw 'Higher release identity differs.' }
        if (-not $item.draft -and -not $item.prerelease) { return $item }
    }
    return $release
}

function Get-CurrentRuntimeTarget([string]$Key) {
    if (-not $script:ResolvedRuntimeTargets) { $script:ResolvedRuntimeTargets = @{} }
    if ($script:ResolvedRuntimeTargets.ContainsKey($Key)) { return $script:ResolvedRuntimeTargets[$Key] }
    $component, $arch = $Key -split '-', 2
    $metadataUrl = $null
    switch ($component) {
        'git' {
            $metadataUrl = 'https://api.github.com/repos/git-for-windows/git/releases/latest'
            $release = Get-CurrentGithubRelease 'git-for-windows/git' -WindowsGit
            if ($release.draft -or $release.prerelease -or $release.tag_name -notmatch '^v(\d+\.\d+\.\d+\.windows\.\d+)$') { throw 'Git for Windows current stable identity is invalid.' }
            $version = $Matches[1]
            $base = $version -replace '\.windows\.\d+$', ''
            $suffix = if ($arch -eq 'x64') { '64-bit' } elseif ($arch -eq 'arm64') { 'arm64' } else { throw 'Unsupported native Git architecture.' }
            $build = ($version -split '\.')[-1]
            $asset = @($release.assets | Where-Object { $_.name -match ('^MinGit-' + [regex]::Escape($base) + '(?:\.' + $build + ')?-' + $suffix + '\.zip$') })
            $name = if ($asset.Count -eq 1) { $asset[0].name } else { 'unavailable/ambiguous native ZIP' }
            if ($asset.Count -ne 1 -or $asset[0].digest -notmatch '^sha256:([a-f0-9]{64})$') { throw "Git $version has no verified $name asset." }
            $sha = $Matches[1]
            $url = "https://github.com/git-for-windows/git/releases/download/$($release.tag_name)/$name"
            if ($asset[0].browser_download_url -cne $url) { throw 'Git release URL differs from official identity.' }
        }
        'python' {
            $metadataUrl = 'https://www.python.org/ftp/python/index-windows.json'
            $next = $metadataUrl; $all = @(); $seen = @{}
            for ($page = 0; $page -lt 16 -and $next; $page++) {
                if ($seen.ContainsKey($next) -or $next -notmatch '^https://www\.python\.org/ftp/python/index-[A-Za-z0-9_.-]+\.json$') { throw 'Unsafe or cyclic Python index pagination.' }
                $seen[$next] = $true
                $index = Invoke-RestMethod -Uri $next -UseBasicParsing -TimeoutSec 20
                $all += @($index.versions)
                $next = if ($index.next) { ([uri]::new([uri]$next, [string]$index.next)).AbsoluteUri } else { $null }
            }
            if ($next) { throw 'Python catalog pagination exhausted; latest stable is unproved.' }
            $stable = @($all | Where-Object { $_.'sort-version' -match '^\d+\.\d+\.\d+$' } | Sort-Object { [version]$_.'sort-version' } -Descending)
            if (-not $stable.Count) { throw 'Python current stable metadata is absent.' }
            $version = $stable[0].'sort-version'
            $suffix = if ($arch -eq 'x64') { '64' } elseif ($arch -eq 'arm64') { 'arm64' } else { throw 'Unsupported Python architecture.' }
            $runtime = @($stable | Where-Object { $_.'sort-version' -ceq $version -and $_.id -match ("^pythoncore-\d+\.\d+-$suffix`$") })
            if ($runtime.Count -ne 1 -or $runtime[0].executable -cne '.\python.exe') { throw "Python $version has no ordinary $arch runtime; no old-family fallback." }
            $url = $runtime[0].url; $sha = $runtime[0].hash.sha256
            if (-not $url.StartsWith("https://www.python.org/ftp/python/$version/python-$version-") -or -not $url.EndsWith('.zip')) { throw 'Python official ZIP identity is invalid.' }
        }
        'pwsh' {
            $metadataUrl = 'https://api.github.com/repos/PowerShell/PowerShell/releases/latest'
            $release = Get-CurrentGithubRelease 'PowerShell/PowerShell'
            if ($release.draft -or $release.prerelease -or $release.tag_name -notmatch '^v(\d+\.\d+\.\d+)$') { throw 'PowerShell current stable identity is invalid.' }
            $version = $Matches[1]; $name = "PowerShell-$version-win-$arch.zip"
            $asset = @($release.assets | Where-Object { $_.name -ceq $name })
            if ($asset.Count -ne 1 -or $asset[0].digest -notmatch '^sha256:([a-f0-9]{64})$') { throw "PowerShell $version has no verified $name asset." }
            $sha = $Matches[1]; $url = "https://github.com/PowerShell/PowerShell/releases/download/v$version/$name"
            if ($asset[0].browser_download_url -cne $url) { throw 'PowerShell official asset identity differs.' }
        }
        'node' {
            $metadataUrl = 'https://nodejs.org/dist/index.json'
            $rows = Invoke-RestMethod -Uri $metadataUrl -UseBasicParsing -TimeoutSec 20
            $stable = @($rows | Where-Object { $_.version -match '^v\d+\.\d+\.\d+$' } | Sort-Object { [version]$_.version.TrimStart('v') } -Descending)
            if (-not $stable.Count) { throw 'Node current stable metadata is absent.' }
            $version = $stable[0].version.TrimStart('v'); $name = "node-v$version-win-$arch.zip"
            if ($stable[0].files -notcontains "win-$arch-zip") { throw "Node $version has no Windows $arch ZIP; no older compatible fallback." }
            $sums = (Invoke-WebRequest -Uri "https://nodejs.org/dist/v$version/SHASUMS256.txt" -UseBasicParsing -TimeoutSec 20).Content
            $line = @(([string]$sums -split "`n") | Where-Object { $_ -match ('^([a-f0-9]{64})  ' + [regex]::Escape($name) + '\r?$') })
            if ($line.Count -ne 1 -or $line[0] -notmatch '^([a-f0-9]{64})  ') { throw 'Node exact versioned SHA256 is absent.' }
            $sha = $Matches[1]; $url = "https://nodejs.org/dist/v$version/$name"
        }
        default { throw "No current release resolver for $Key." }
    }
    if ($sha -notmatch '^[a-f0-9]{64}$') { throw "$component $version has no official SHA256." }
    $target = @{ Url = $url; Sha256 = $sha; Version = $version; Metadata = $metadataUrl }
    $script:ResolvedRuntimeTargets[$Key] = $target
    return $target
}

function Install-CurrentRuntime([string]$Component) {
    $arch = Get-WindowsArchitecture
    $target = Get-CurrentRuntimeTarget "$Component-$arch"
    $name = "Getzilla\runtimes\$Component-$($target.Version)-$($target.Sha256.Substring(0,16))"
    $folder = Expand-ToUserPrograms (Get-PinnedDownload "$Component-$arch") $name
    $relative = switch ($Component) { 'git' { 'cmd\git.exe' } 'python' { 'python.exe' } 'pwsh' { 'pwsh.exe' } 'node' { 'node.exe' } }
    $binary = Join-Path $folder $relative
    if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) { throw "$Component current archive has no $relative." }
    $text = & $binary --version 2>$null
    if ($LASTEXITCODE -ne 0 -or "$text" -notmatch ('(?<![\w.])' + [regex]::Escape($target.Version) + '(?![\w.])')) { throw "$Component target=$($target.Version) path=$binary actual version probe failed." }
    Add-UserPath (Split-Path $binary)
    $command = if ($Component -eq 'pwsh') { 'pwsh' } elseif ($Component -eq 'python') { 'python' } else { $Component }
    $active = Get-Command $command -ErrorAction SilentlyContinue
    if (-not $active -or $active.Source -ine $binary) { throw "$Component PATH conflict: expected $binary; actual $($active.Source)." }
    Write-Step "$Component target=$($target.Version) actual=$($target.Version) path=$binary (official SHA256 verified)"
    return $binary
}

try {
    Install-Getzilla
} catch {
    Write-Host ("ERROR: " + $_.Exception.Message) -ForegroundColor Red
    throw
}
