#!/usr/bin/env bash
# Owner build/audit tooling only; never required by the installed Rust scanner.
set -euo pipefail
work=$1
[[ "$work" == /* && -d "$work" && ! -e "$work/go" ]]
curl --disable --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
  --max-time 120 --max-filesize 268435456 \
  https://go.dev/dl/go1.27.3.linux-amd64.tar.gz -o "$work/go.tgz"
printf '%s  %s\n' 65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40 "$work/go.tgz" | sha256sum -c --strict
tar -xzf "$work/go.tgz" -C "$work"
rm "$work/go.tgz"
