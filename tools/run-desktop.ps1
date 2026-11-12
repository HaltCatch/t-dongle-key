param(
    [switch]$Demo,
    [switch]$Test,
    [switch]$ReleaseTest,
    [string]$Distribution = 'ubuntu'
)
$ErrorActionPreference = 'Stop'
$repoPath = Split-Path -Parent $PSScriptRoot
$linuxPath = (& wsl.exe -d $Distribution --exec wslpath -a $repoPath).Trim()
if ($LASTEXITCODE -ne 0) { throw 'WSL could not resolve the repository path.' }
$arguments = @('-d', $Distribution, '--exec', 'bash', "$linuxPath/tools/run-desktop.sh")
if ($ReleaseTest) { $arguments += '--release-test' }
elseif ($Test) { $arguments += '--test' }
elseif ($Demo) { $arguments += '--demo' }
& wsl.exe @arguments
exit $LASTEXITCODE
