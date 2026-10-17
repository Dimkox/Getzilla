# Baseline for Getzilla's own installers (scripts/install.ps1, scripts/bootstrap.ps1), recorded
# 2026-10-17 with PSScriptAnalyzer 1.25.0. Every other rule stays on: a new finding fails verification.
@{
    Severity     = @('Error', 'Warning')
    ExcludeRules = @(
        # The installers talk to a person at a console; Write-Host is the intended channel.
        'PSAvoidUsingWriteHost',
        # Update-SessionPath, Update-SecurityData and Set-AgentConfiguration are internal helpers, not cmdlets.
        'PSUseShouldProcessForStateChangingFunctions',
        # Helper names describe collections (Test-WingetInstalls, Select-WingetDependencies, Expand-ToUserPrograms).
        'PSUseSingularNouns',
        # False positive: `2>$null` inside an if condition is stderr redirection, not a comparison.
        'PSPossibleIncorrectUsageOfRedirectionOperator'
    )
}
