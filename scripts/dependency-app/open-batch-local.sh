#!/usr/bin/env bash
set -euo pipefail
ulimit -c 0
if (( $# == 0 )); then
  printf '%s\n' 'Pass the reviewed local configuration paths, one per organization.' >&2
  exit 1
fi
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
for config in "$@"; do
  bash "$script_dir/open-local.sh" "$config"
done
printf '%s\n' 'All requested owner registrations finished. Rules and activation are unchanged.'
