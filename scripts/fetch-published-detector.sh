#!/usr/bin/env bash
# Fetch only immutable reviewed bytes; no source compilation or implicit latest.
set -euo pipefail
output=$1
[[ "$output" == /* && ! -e "$output" && ! -L "$output" ]]
mkdir -m 700 "$output"
pin=tests/gitleaks-pin.json
url=$(jq -er '.url' "$pin")
digest=$(jq -er '.archive_sha256' "$pin")
source=$(jq -er '.source' "$pin")
[[ "$url" == https://github.com/zixcel/zixcel-repository-security/releases/download/gitleaks/* ]]
[[ "$digest" =~ ^[a-f0-9]{64}$ && "$source" =~ ^[a-f0-9]{40}$ ]]
archive="$output/engine.tar.gz"
curl --disable --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
  --max-time 120 --max-filesize 67108864 "$url" --output "$archive"
printf '%s  %s\n' "$digest" "$archive" | sha256sum --check --strict
gh attestation verify "$archive" --repo zixcel/zixcel-repository-security \
  --signer-workflow zixcel/zixcel-repository-security/.github/workflows/publish-detector.yml \
  --source-digest "$source" --signer-digest "$source" --source-ref refs/heads/main \
  --deny-self-hosted-runners --format json > "$output/provenance.json"
