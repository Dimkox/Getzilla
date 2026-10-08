# Getzilla installer for Windows (Windows PowerShell 5.1 or PowerShell 7).
#
#   irm https://raw.githubusercontent.com/Dimkox/Getzilla/main/scripts/install.ps1 | iex
#
# Installs what is missing (Git, Python 3.13, your coding agent), downloads Getzilla,
# points the agent at its models and runs its health check. Uses winget when it is available; otherwise it downloads the
# official installers and installs them for the current user, without administrator
# rights. Nothing is changed in your projects unless you ask for it below.
#
# Optional environment variables (set them before the command above):
#   $env:GETZILLA_HOME = 'D:\Tools\Getzilla'   where Getzilla is kept (default: $HOME\Getzilla)
#   $env:GETZILLA_REF = 'main'                  branch or tag to install
#   $env:GETZILLA_REPO = 'https://...'          Git URL to install from
#   $env:GETZILLA_PROJECT = 'C:\code\my-app'    existing project: print the read-only install plan
#   $env:GETZILLA_NEW_PROJECT = 'C:\code\new'   create a new project there (the folder must not exist)
#   $env:GETZILLA_AGENT = 'qwen'                qwen | codex | claude | grok (default: ask, else qwen)
#   $env:GETZILLA_PROVIDER = 'openrouter'       openrouter | native sign-in (default: ask, else openrouter)
#   $env:GETZILLA_MODEL = 'qwen/qwen3-coder'    OpenRouter model id for Qwen Code or Codex
#   $env:OPENROUTER_API_KEY = '...'             your OpenRouter key (otherwise asked for, never echoed)
#   $env:GETZILLA_SKIP_AGENT = '1'              do not install or configure the coding agent
#   $env:GETZILLA_SKIP_GROK = '1'               do not install the Grok Build CLI (when the agent is grok)
#   $env:GETZILLA_NONINTERACTIVE = '1'          never ask; use the defaults above
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
        switch (Read-Choice 'Coding agent: 1) Qwen Code  2) Codex  3) Claude Code  4) Grok Build  [1]' '1') {
            { $_ -in @('2', 'codex') } { $agent = 'codex'; break }
            { $_ -in @('3', 'claude') } { $agent = 'claude'; break }
            { $_ -in @('4', 'grok') } { $agent = 'grok'; break }
            default { $agent = 'qwen' }
        }
    }
    if ($agent -notin @('qwen', 'codex', 'claude', 'grok')) {
        throw "GETZILLA_AGENT must be qwen, codex, claude or grok (got '$agent')."
    }
    return $agent
}

function Select-Provider([string]$Agent) {
    if ($Agent -eq 'grok') { return 'native' }
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
        'grok' { return 'grok   (first time: sign in, then type /hooks-trust)' }
        default { return 'qwen' }
    }
}

function Install-Agent([string]$Agent) {
    switch ($Agent) {
        'qwen' { Install-NpmAgent 'qwen' '@qwen-code/qwen-code@latest' 'Qwen Code' }
        'codex' { Install-NpmAgent 'codex' '@openai/codex@latest' 'Codex CLI' }
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

function Test-Node {
    if (-not (Get-Command node -ErrorAction SilentlyContinue)) { return $false }
    $major = (& node -e 'console.log(process.versions.node.split(".")[0])' 2>$null)
    return ([int]"$major" -ge 20)
}

function Install-Node {
    if (Test-Node) { return $true }
    Write-Step 'Installing Node.js LTS (20 or newer is needed)...'
    if ((Test-Winget) -and (Invoke-Winget 'OpenJS.NodeJS.LTS' @())) { Update-SessionPath }
    if (Test-Node) { return $true }
    Write-Step 'Node.js 20 or newer is still missing. Install it from https://nodejs.org and run this installer again.'
    return $false
}

function Install-NpmAgent([string]$Command, [string]$Package, [string]$Label) {
    if (Get-Command $Command -ErrorAction SilentlyContinue) {
        Write-Step "${Label}: already installed."
        return
    }
    if (-not (Install-Node)) { return }
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
    $key = $env:OPENROUTER_API_KEY
    if ($Provider -eq 'openrouter' -and $Agent -ne 'grok' -and -not $key -and (Test-CanAsk)) {
        try {
            $secure = Read-Host 'OpenRouter API key (create one at https://openrouter.ai/keys, Enter to skip)' -AsSecureString
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
        $saved = $env:OPENROUTER_API_KEY
        $env:OPENROUTER_API_KEY = $null
        try {
            $null | & $exe @prefix @arguments
        } finally {
            $env:OPENROUTER_API_KEY = $saved
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
