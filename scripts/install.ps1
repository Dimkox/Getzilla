# Getzilla installer for Windows (Windows PowerShell 5.1 or PowerShell 7).
#
#   irm https://raw.githubusercontent.com/Dimkox/Getzilla/main/scripts/install.ps1 | iex
#
# Installs what is missing (Git, Python 3.13, your coding agent), downloads Getzilla,
# points the agent at its models and runs its health check. Uses winget when it is available; otherwise it downloads the
# official installers and installs them for the current user, without administrator
# rights. Nothing is changed in your projects unless you ask for it below.
#
# Minimum versions: Windows PowerShell 5.1 can run this installer; Getzilla itself needs
# PowerShell 7.4 or newer (pwsh), which this installer adds with winget when it is missing,
# because agent hooks use the && and || operators that Windows PowerShell 5.1 lacks.
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
#   $env:GETZILLA_NONINTERACTIVE = '1'          never ask; use the defaults above
#   $env:GETZILLA_SKIP_WINGET = '1'             do not install winget when it is missing
#
# At the end of every run (first install or re-run) the installer offers to update
# third-party tools to their latest versions (agent CLIs, Superpowers, BMAD, Spec Kit,
# vibevm, the CVE database, OpenGrep) and runs scripts/getzilla_update.py only after you
# answer yes. Without an interactive console it only prints that command.
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

    Initialize-Winget

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

    Install-PowerShell7

    $Agent = Select-Agent
    $Provider = Select-Provider $Agent
    Write-Step "Coding agent: $Agent (models: $Provider)"
    if ($env:GETZILLA_SKIP_AGENT -eq '1') {
        Write-Step 'Skipping the coding agent (GETZILLA_SKIP_AGENT=1).'
    } else {
        Install-Agent $Agent
    }

    Get-GetzillaSource -Repo $Repo -Ref $Ref -Destination $GetzillaHome

    Push-Location $GetzillaHome
    try {
        if ($env:GETZILLA_SKIP_AGENT -ne '1') { Set-AgentConfiguration $Python $Agent $Provider }
        Write-Step 'Checking this machine...'
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

    Request-ToolUpdate $Python $GetzillaHome

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
    Write-Host ('  2. In your project run: ' + (Get-AgentCommand $Agent))
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
    if (Test-Winget) {
        Write-Step ('winget: ' + ((& winget --version) | Select-Object -First 1))
        return
    }
    if ($env:GETZILLA_SKIP_WINGET -eq '1') {
        Write-Step 'winget is missing; skipping its installation (GETZILLA_SKIP_WINGET=1). Using direct downloads.'
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
    $release = Invoke-RestMethod -Uri 'https://api.github.com/repos/microsoft/winget-cli/releases/latest' -UseBasicParsing
    $bundle = $release.assets | Where-Object { $_.name -eq 'Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle' } | Select-Object -First 1
    $dependencies = $release.assets | Where-Object { $_.name -eq 'DesktopAppInstaller_Dependencies.zip' } | Select-Object -First 1
    if (-not $bundle) { return $false }
    $paths = @()
    if ($dependencies) {
        $zip = Get-Download $dependencies.browser_download_url $dependencies.name
        $folder = Join-Path ([System.IO.Path]::GetTempPath()) 'getzilla-winget-dependencies'
        if (Test-Path $folder) { Remove-Item -Recurse -Force $folder }
        Expand-Archive -Path $zip -DestinationPath $folder -Force
        Remove-Item -Force $zip
        $paths = Select-WingetDependencies $folder (Get-WindowsArchitecture)
    }
    $package = Get-Download $bundle.browser_download_url $bundle.name
    if ($paths.Count) {
        Add-AppxPackage -Path $package -DependencyPath $paths -ErrorAction Stop
    } else {
        Add-AppxPackage -Path $package -ErrorAction Stop
    }
    Remove-Item -Force $package
    $apps = Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps'
    if (($env:Path -split ';') -notcontains $apps) { $env:Path = "$env:Path;$apps" }
    return (Test-Winget)
}

function Expand-ToUserPrograms([string]$Zip, [string]$Name) {
    $target = Join-Path $env:LOCALAPPDATA "Programs\$Name"
    $staging = Join-Path ([System.IO.Path]::GetTempPath()) "getzilla-$Name"
    foreach ($path in @($target, $staging)) { if (Test-Path $path) { Remove-Item -Recurse -Force $path } }
    Expand-Archive -Path $Zip -DestinationPath $staging -Force
    Remove-Item -Force $Zip
    $children = @(Get-ChildItem -Path $staging)
    $source = $staging
    if ($children.Count -eq 1 -and $children[0].PSIsContainer) { $source = $children[0].FullName }
    New-Item -ItemType Directory -Force -Path (Split-Path $target) | Out-Null
    Move-Item -Path $source -Destination $target
    if (Test-Path $staging) { Remove-Item -Recurse -Force $staging }
    return $target
}

function Select-NodeLts($Index, [int]$Minimum) {
    foreach ($release in $Index) {
        if (-not $release.lts) { continue }
        $major = [int]("$($release.version)".TrimStart('v').Split('.')[0])
        if ($major -ge $Minimum) { return "$($release.version)" }
    }
    return $null
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

$MinimumPowerShell = [version]'7.4'

function Get-Pwsh {
    $command = Get-Command pwsh -ErrorAction SilentlyContinue
    if (-not $command) { return $null }
    try {
        $text = (& $command.Source -NoProfile -Command '$PSVersionTable.PSVersion.ToString()' 2>$null | Select-Object -First 1)
        $version = [version](("$text".Trim()) -replace '[^0-9.].*$', '')
    } catch {
        return $null
    }
    return [pscustomobject]@{ Path = $command.Source; Version = $version }
}

function Install-PowerShell7 {
    $pwsh = Get-Pwsh
    if ($pwsh -and $pwsh.Version -ge $MinimumPowerShell) {
        Write-Step ("PowerShell: " + $pwsh.Version)
        return
    }
    Write-Step "Installing PowerShell $MinimumPowerShell or newer (Getzilla's minimum)..."
    if ((Test-Winget) -and (Invoke-Winget 'Microsoft.PowerShell' @())) { Update-SessionPath }
    $pwsh = Get-Pwsh
    if (-not ($pwsh -and $pwsh.Version -ge $MinimumPowerShell)) {
        try {
            $release = Invoke-RestMethod -Uri 'https://api.github.com/repos/PowerShell/PowerShell/releases/latest' -UseBasicParsing
            $pattern = '^PowerShell-[0-9.]+-win-' + (Get-WindowsArchitecture) + '\.zip$'
            $asset = $release.assets | Where-Object { $_.name -match $pattern } | Select-Object -First 1
            if ($asset) {
                $folder = Expand-ToUserPrograms (Get-Download $asset.browser_download_url $asset.name) 'PowerShell7'
                Add-UserPath $folder
            }
        } catch {
            Write-Verbose $_.Exception.Message
        }
        $pwsh = Get-Pwsh
    }
    if ($pwsh -and $pwsh.Version -ge $MinimumPowerShell) {
        Write-Step ("PowerShell: " + $pwsh.Version)
    } else {
        Write-Step "PowerShell $MinimumPowerShell or newer is still missing. Install it from https://aka.ms/powershell-release?tag=lts and open agents from a PowerShell 7 window."
    }
}

function Request-ToolUpdate([string[]]$Python, [string]$GetzillaHome) {
    $answer = 'n'
    if (Test-CanAsk) {
        $answer = Read-Choice 'Update third-party tools (agent CLIs, Superpowers, BMAD, Spec Kit, vibevm, CVE database, OpenGrep) to their latest versions now? [y/N]' 'n'
    }
    if ($answer -in @('y', 'Y', 'yes', 'Yes', 'YES')) {
        Write-Step 'Updating third-party tools...'
        Push-Location $GetzillaHome
        try {
            Invoke-Python $Python @('scripts/getzilla_update.py')
            if ($LASTEXITCODE -ne 0) { Write-Step 'Some updates failed (FAIL lines above); run the same command again later.' }
        } finally {
            Pop-Location
        }
    } else {
        Write-Step ("Third-party tools were not updated. To update them: cd `"$GetzillaHome`"; " + ($Python -join ' ') + ' scripts/getzilla_update.py')
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

function Install-Agent([string]$Agent) {
    switch ($Agent) {
        'qwen' { Install-NpmAgent 'qwen' '@qwen-code/qwen-code@latest' 'Qwen Code' }
        'codex' { Install-NpmAgent 'codex' '@openai/codex@latest' 'Codex CLI' }
        'gemini' { Install-NpmAgent 'gemini' '@google/gemini-cli@latest' 'Gemini CLI' }
        'copilot' { Install-NpmAgent 'copilot' '@github/copilot@latest' 'Copilot CLI' 22 }
        'claude' { Install-Claude }
        'grok' {
            if ($env:GETZILLA_SKIP_GROK -eq '1') {
                Write-Step 'Skipping the Grok Build CLI (GETZILLA_SKIP_GROK=1).'
            } else {
                Install-Grok
            }
        }
    }
}

function Test-Node([int]$Minimum = 20) {
    if (-not (Get-Command node -ErrorAction SilentlyContinue)) { return $false }
    $major = (& node -e 'console.log(process.versions.node.split(".")[0])' 2>$null)
    return ([int]"$major" -ge $Minimum)
}

function Install-Node([int]$Minimum = 20) {
    if (Test-Node $Minimum) { return $true }
    Write-Step "Installing Node.js LTS ($Minimum or newer is needed)..."
    if ((Test-Winget) -and (Invoke-Winget 'OpenJS.NodeJS.LTS' @())) { Update-SessionPath }
    if (Test-Node $Minimum) { return $true }
    try {
        $version = Select-NodeLts (Invoke-RestMethod -Uri 'https://nodejs.org/dist/index.json' -UseBasicParsing) $Minimum
        if ($version) {
            $name = "node-$version-win-$(Get-WindowsArchitecture).zip"
            $folder = Expand-ToUserPrograms (Get-Download "https://nodejs.org/dist/$version/$name" $name) 'nodejs'
            Add-UserPath $folder
            Add-UserPath (Join-Path $env:APPDATA 'npm')
        }
    } catch {
        Write-Verbose $_.Exception.Message
    }
    if (Test-Node $Minimum) { return $true }
    Write-Step "Node.js $Minimum or newer is still missing. Install it from https://nodejs.org and run this installer again."
    return $false
}

function Install-NpmAgent([string]$Command, [string]$Package, [string]$Label, [int]$NodeMinimum = 20) {
    if (Get-Command $Command -ErrorAction SilentlyContinue) {
        Write-Step "${Label}: already installed."
        return
    }
    if (-not (Install-Node $NodeMinimum)) { return }
    Write-Step "Installing $Label..."
    & npm install -g $Package | Out-Null
    Update-SessionPath
    if (Get-Command $Command -ErrorAction SilentlyContinue) {
        Write-Step "$Label installed."
    } else {
        Write-Step "Could not install $Label now. Later run: npm install -g $Package"
    }
}

function Install-Claude {
    if (Get-Command claude -ErrorAction SilentlyContinue) {
        Write-Step 'Claude Code: already installed.'
        return
    }
    Write-Step 'Installing Claude Code...'
    $shell = (Get-Process -Id $PID).Path
    & $shell -NoProfile -ExecutionPolicy Bypass -Command 'irm https://claude.ai/install.ps1 | iex' | Out-Null
    Add-UserPath (Join-Path $HOME '.local\bin')
    if (Get-Command claude -ErrorAction SilentlyContinue) {
        Write-Step 'Claude Code installed.'
    } else {
        Write-Step 'Claude Code: if it is not found, open a new PowerShell window. To retry: irm https://claude.ai/install.ps1 | iex'
    }
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
