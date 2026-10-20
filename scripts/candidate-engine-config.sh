#!/usr/bin/env bash
# CI-only configuration for already audited candidate bytes; never a release pin.
set -euo pipefail
umask 077
engine=$1
output=$2
[[ "$engine" == /* && "$output" == /* && ! -e "$output" ]] || exit 1
[[ -f "$engine/gitleaks" && ! -L "$engine/gitleaks" ]] || exit 1
[[ -s "$engine/vulnerabilities.jsonl" && -s "$engine/binary-inventory.jsonl" ]] || exit 1
sha=$(sha256sum "$engine/gitleaks" | cut -d ' ' -f 1)
jq -n --arg path "$engine/gitleaks" --arg sha "$sha" \
    '{repository_id:"synthetic-source",gitleaks:{path:$path,sha256:$sha}}' > "$output"
