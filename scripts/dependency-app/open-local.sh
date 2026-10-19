#!/usr/bin/env bash
set -euo pipefail
[[ $# == 1 ]] || { echo 'Usage: open-local.sh /absolute/path/to/local-config.json' >&2; exit 2; }
ulimit -c 0
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
exec node "$root/scripts/dependency-app/main.mts" "$1"
