$ErrorActionPreference = 'Stop'
$gitBash = Join-Path $env:ProgramFiles 'Git/bin/bash.exe'
if (-not (Test-Path -LiteralPath $gitBash)) { throw 'Install Git for Windows first.' }
$repoPath = (Split-Path -Parent $PSScriptRoot).Replace('\', '/')
$script = @'
export MSYS2_ENV_CONV_EXCL=GIT_SSH_COMMAND
export GIT_SSH_COMMAND="${GIT_SSH_COMMAND:-/c/Windows/System32/OpenSSH/ssh.exe -o BatchMode=yes -o StrictHostKeyChecking=yes}"
cd "$1"
exec bash tools/checkout-deps.sh
'@
& $gitBash --noprofile --norc -c $script tdongle-deps $repoPath
exit $LASTEXITCODE
