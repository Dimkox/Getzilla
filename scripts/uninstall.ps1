# Getzilla uninstaller for Windows: the reverse of scripts/install.ps1.
#
#   & "$HOME\Getzilla\scripts\uninstall.ps1"            show the plan and ask
#   & "$HOME\Getzilla\scripts\uninstall.ps1" --dry-run  show the plan only
#   & "$HOME\Getzilla\scripts\uninstall.ps1" --yes      do not ask
#
# Same options as `getzilla self-uninstall --help`. Windows cannot delete a running
# Python, so this script removes the remaining folders after Python exits.
# Your projects, winget packages and vendor-installed agents are not changed.

function Uninstall-Getzilla([string[]]$Arguments) {
    $GetzillaHome = if ($env:GETZILLA_HOME) { $env:GETZILLA_HOME } else { Split-Path -Parent $PSScriptRoot }
    $core = Join-Path $GetzillaHome 'scripts\getzilla_self_uninstall.py'
    if (-not (Test-Path -LiteralPath $core -PathType Leaf)) { throw "$core not found. Set GETZILLA_HOME to the Getzilla folder." }
    $python = Join-Path $GetzillaHome '.venv\Scripts\python.exe'
    if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
        $found = Get-Command python -ErrorAction SilentlyContinue
        if (-not $found) { throw 'Python 3.10 or newer is required.' }
        $python = $found.Source
    }
    $deferred = Join-Path $env:TEMP ('getzilla-uninstall-' + [guid]::NewGuid().ToString('N') + '.txt')
    try {
        & $python $core --home $GetzillaHome --deferred-file $deferred @Arguments
        $code = $LASTEXITCODE
        if (Test-Path -LiteralPath $deferred) {
            Set-Location -LiteralPath $HOME  # a folder in use as the current location cannot be removed
            foreach ($folder in Get-Content -LiteralPath $deferred) {
                if (-not $folder -or -not (Test-Path -LiteralPath $folder)) { continue }
                Get-ChildItem -LiteralPath $folder -Recurse -Force -ErrorAction SilentlyContinue |
                    ForEach-Object { try { $_.Attributes = 'Normal' } catch { } }
                Remove-Item -LiteralPath $folder -Recurse -Force
                Write-Host "removed: $folder"
            }
        }
        # Drop Getzilla folders from this window's PATH too.
        $env:Path = (@($env:Path -split ';' | Where-Object { $_ -and (Test-Path -LiteralPath $_) }) -join ';')
        return $code
    } finally {
        if (Test-Path -LiteralPath $deferred) { Remove-Item -LiteralPath $deferred -Force }
    }
}

try {
    $exitCode = Uninstall-Getzilla $args
    if ($exitCode) { Write-Host "Uninstall finished with exit code $exitCode." }
    $global:LASTEXITCODE = $exitCode  # no `exit`: it would close an interactive window
} catch {
    Write-Host "ERROR: $_" -ForegroundColor Red
    $global:LASTEXITCODE = 1
}
