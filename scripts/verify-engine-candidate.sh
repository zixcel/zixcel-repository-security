#!/usr/bin/env bash
# Hash-bound read-only verification; no extraction, network, or publication.
set -euo pipefail
directory=$1
source_sha=$2
[[ "$source_sha" =~ ^[a-f0-9]{40}$ && "$directory" == /* && ! -L "$directory" ]]
[[ -f "$directory/candidate.json" && ! -L "$directory/candidate.json" ]]
[[ $(stat -c %s "$directory/candidate.json") -le 16384 ]]
component=$(cat "$(dirname "$0")/gitleaks/component.json")
jq -e --arg source "$source_sha" --argjson component "$component" '
  .schema == 1 and .repository == "zixcel/zixcel-repository-security" and
  .source == $source and .detectorVersion == "8.30.1" and .platform == "linux-amd64" and
  .releaseTag == $component.tag and .origin == $component.origin and .build == $component.build and
  (.executableSha256 | test("^[a-f0-9]{64}$")) and
  (.files | keys == ["binary-inventory.jsonl","gitleaks_8.30.1_hardened_linux_x64.tar.gz",
    "go.mod","go.sum","imports.json","vulnerabilities.jsonl"]) and
  all(.files[]; test("^[a-f0-9]{64}$"))' "$directory/candidate.json" >/dev/null
actual=$(find "$directory" -mindepth 1 -maxdepth 1 -printf '%f\n' | LC_ALL=C sort)
expected=$(jq -r '.files|keys[]' "$directory/candidate.json"; printf '%s\n' candidate.json)
test "$actual" = "$(printf '%s\n' "$expected" | LC_ALL=C sort)"
while IFS=$'\t' read -r file expected; do
  [[ -f "$directory/$file" && ! -L "$directory/$file" ]]
  [[ $(stat -c %s "$directory/$file") -le 67108864 ]]
  test "$(sha256sum "$directory/$file" | cut -d ' ' -f 1)" = "$expected"
done < <(jq -r '.files|to_entries[]|[.key,.value]|@tsv' "$directory/candidate.json")
executable_sha=$(timeout 20s tar -xOzf "$directory/gitleaks_8.30.1_hardened_linux_x64.tar.gz" -- gitleaks |
  head -c 67108865 | sha256sum | cut -d ' ' -f 1)
test "$executable_sha" = "$(jq -r '.executableSha256' "$directory/candidate.json")"
jq -s -e '[.[]|select(.finding.trace[0].package)]|length == 0' "$directory/vulnerabilities.jsonl" >/dev/null
jq -s -e '.[1].pkgSymbols|length > 0' "$directory/binary-inventory.jsonl" >/dev/null
bash "$(dirname "$0")/verify-binary-audit.sh" "$directory/vulnerabilities.jsonl" "$directory/binary-inventory.jsonl" "$directory/imports.json"
