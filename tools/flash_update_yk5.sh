#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
exec uv run --no-project --with esptool==5.6.0 python "$root/tools/flash_app.py" "$@"
