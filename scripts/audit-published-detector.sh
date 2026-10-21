#!/usr/bin/env bash
# Freshly audit the actual published executable, never rebuild its obsolete recipe.
set -euo pipefail
: "${RUNNER_TEMP:?}"
work=$(mktemp -d "$RUNNER_TEMP/published-audit.XXXXXX")
trap 'chmod -R u+w -- "$work"; rm -rf -- "$work"' EXIT
bash scripts/fetch-published-detector.sh "$work/published"
mkdir -m 700 "$work/executable"
timeout 20s tar -xOzf "$work/published/engine.tar.gz" -- gitleaks | head -c 67108865 > "$work/executable/gitleaks"
expected=$(jq -er '.executable_sha256' tests/gitleaks-pin.json)
printf '%s  %s\n' "$expected" "$work/executable/gitleaks" | sha256sum -c --strict
bash scripts/prepare-detector-go.sh "$work"
export GOENV=off GOTOOLCHAIN=local GOPATH="$work/modules" GOCACHE="$work/cache" GOMAXPROCS=2 GOFLAGS=-p=2
GOBIN="$work/bin" "$work/go/bin/go" install golang.org/x/vuln/cmd/govulncheck@v1.8.0
output=${1:?Evidence directory required}
mkdir -m 700 "$output"
"$work/bin/govulncheck" -mode=extract "$work/executable/gitleaks" > "$output/binary-inventory.jsonl"
jq -s -e '.[1].pkgSymbols|length > 0' "$output/binary-inventory.jsonl" >/dev/null
"$work/bin/govulncheck" -mode=binary -json "$work/executable/gitleaks" > "$output/vulnerabilities.jsonl"
# Preserve actual findings even when an old artifact lacks import-graph evidence.
if ! timeout 20s tar -xOzf "$work/published/engine.tar.gz" -- imports.json | head -c 1048577 > "$work/imports.json"; then
  echo '::error::Published archive lacks its audited import graph; replace the pin.' >&2
  jq -c 'select(.finding) | .finding' "$output/vulnerabilities.jsonl" >&2
  exit 1
fi
[[ $(stat -c %s "$work/imports.json") -le 1048576 ]]
if ! bash scripts/verify-binary-audit.sh "$output/vulnerabilities.jsonl" "$output/binary-inventory.jsonl" "$work/imports.json"; then
  echo '::error::Published detector audit failed; replace the pin. See retained findings.' >&2
  jq -c 'select(.finding) | .finding' "$output/vulnerabilities.jsonl" >&2
  exit 1
fi
