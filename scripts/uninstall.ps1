# Invoke the checkout containing this launcher and propagate the CLI status.
$launcher = Join-Path (Split-Path -Parent $PSScriptRoot) 'bin/getzilla.cmd'
& $launcher self-uninstall @args
exit $LASTEXITCODE
