#!/usr/bin/env bash
# Record audited detector bytes after the source CI has passed its actual tests.
set -euo pipefail
umask 077
engine=$1
output=$2
source_sha=${GITHUB_SHA:?Accepted source identity required}
[[ "$source_sha" =~ ^[a-f0-9]{40}$ && "$engine" == /* && "$output" == /* ]]
[[ ! -e "$output" && ! -L "$output" ]]
archive=gitleaks_8.30.1_hardened_linux_x64.tar.gz
files=("$archive" go.mod go.sum imports.json binary-inventory.jsonl vulnerabilities.jsonl)
for file in "${files[@]}" gitleaks; do
  [[ -s "$engine/$file" && -f "$engine/$file" && ! -L "$engine/$file" ]]
done
jq -s -e '[.[]|select(.finding.trace[0].package)]|length == 0' "$engine/vulnerabilities.jsonl" >/dev/null
jq -s -e '.[1].pkgSymbols|length > 0' "$engine/binary-inventory.jsonl" >/dev/null
mkdir -m 700 "$output"
hashes='{}'
for file in "${files[@]}"; do
  install -m 644 "$engine/$file" "$output/$file"
  sha=$(sha256sum "$output/$file" | cut -d ' ' -f 1)
  hashes=$(jq -cn --argjson files "$hashes" --arg file "$file" --arg sha "$sha" '$files+{($file):$sha}')
done
executable_sha=$(sha256sum "$engine/gitleaks" | cut -d ' ' -f 1)
jq -n --arg source "$source_sha" --arg executable "$executable_sha" --argjson files "$hashes" \
  '{schema:1,repository:"zixcel/zixcel-repository-security",source:$source,
    detectorVersion:"8.30.1",platform:"linux-amd64",executableSha256:$executable,files:$files}' > "$output/candidate.json"
bash "$(dirname "$0")/verify-engine-candidate.sh" "$output" "$source_sha"
